package injectcheck

import (
	"maps"

	"github.com/cilium/ebpf/asm"
)

type value struct {
	id    int
	ptr   int
	frame bool
}
type cell struct {
	v     value
	width int
}
type state struct {
	regs  [11]value
	stack map[int]cell
	calls int
}

func initial() state {
	s := state{stack: map[int]cell{}}
	for r := range s.regs {
		s.regs[r] = value{id: r + 1}
	}
	s.regs[10] = value{id: idFrame, frame: true}
	return s
}
func (s state) clone() state { s.stack = maps.Clone(s.stack); return s }
func (s *state) store(at, width int, v value) {
	for k, c := range s.stack {
		if k < at+width && at < k+c.width {
			delete(s.stack, k)
		}
	}
	s.stack[at] = cell{v, width}
}
func width(ins asm.Instruction) int { return int(ins.OpCode.Size().Sizeof()) }

func checkAfter(helper asm.Instruction, before, is, out asm.Instructions, pcs []int, idx map[int]int, js []int, hooks map[int]bool, f int, entryCtx bool) error {
	isLookup := asm.BuiltinFunc(helper.Constant) == asm.FnMapLookupElem || asm.BuiltinFunc(helper.Constant) == asm.FnMapLookupPercpuElem
	tail := asm.BuiltinFunc(helper.Constant) == asm.FnTailCall
	if len(is) == 0 {
		return reject(PostludeMissing, "missing helper observation postlude")
	}
	// Helper postludes assume verifier-accepted originals: R1-R5 are unreadable after a helper,
	// and RET_VOID tail-call failure also leaves R0 unreadable. P2-P5 may
	// clobber these registers even when syntactic liveness includes infeasible
	// paths. R0 is restored for other helpers; P6 still needs liveness because
	// its load does not invalidate caller-saved registers.
	if !tail {
		// P2/P3 save the result once, optionally after loading saved flags.
		save := 0
		if is[0].OpCode.Class() == asm.LdXClass {
			save = 1
		}
		if len(is) <= save+1 || !same(is[save], asm.StoreMem(asm.RFP, int16(f+slotResult), asm.R0, asm.DWord)) || !same(is[len(is)-1], asm.LoadMem(asm.R0, asm.RFP, int16(f+slotResult), asm.DWord)) {
			return reject(ResultSaveRestore, "missing full-width R0 save/restore")
		}
	}
	branches, calls, conditions := 0, 0, 0
	for _, ins := range is {
		if ins.IsFunctionCall() {
			calls++
		}
		if ins.OpCode.Class().IsJump() && !ins.IsFunctionCall() {
			branches++
			if ins.OpCode.JumpOp() != asm.Ja {
				conditions++
			}
		}
	}
	if isLookup {
		if calls < 1 || calls > 2 || conditions != 1 || branches != calls || len(is) < 2 || (is[1].OpCode.JumpOp() != asm.JEq && is[1].OpCode.JumpOp() != asm.JNE) {
			return reject(LookupStructure, "not a lookup branch/call structure")
		}
	} else if calls != 1 || branches > 1 || conditions != branches || tail && branches != 0 {
		return reject(HelperStructure, "not a non-lookup helper branch/call structure")
	}
	s := initial()
	if entryCtx {
		s.stack[f+slotContext] = cell{value{id: idContext}, 8}
	}
	for _, ins := range before {
		s.store(int(ins.Offset), 8, s.regs[ins.Src])
	}
	s.regs[0] = value{id: idResult}
	for r := 1; r <= 5; r++ {
		s.regs[r] = value{}
	}
	if tail {
		s.regs[0] = value{}
	}
	var walk func(int, state) error
	visits := 0
	walk = func(i int, s state) error {
		visits++
		if visits > postludeBudget {
			return reject(PathBudget, "postlude path budget exceeded")
		}
		if i == len(is) {
			if !tail && s.regs[0].id != idResult {
				return reject(ResultPath, "R0 not restored on every path")
			}
			return nil
		}
		ins := is[i]
		cl := ins.OpCode.Class()
		if ins.Dst > asm.RFP || ins.Src > asm.RFP {
			return reject(RegisterInvalid, "invalid register")
		}
		read := func(r asm.Register) error {
			if r > asm.R5 && r != asm.RFP {
				return reject(RegisterRead, "inserted read of R%d outside helper observation", r)
			}
			if s.regs[r].id == idUndefined {
				return reject(RegisterUndefined, "read of undefined R%d at postlude %d", r, i)
			}
			return nil
		}
		switch {
		case cl == asm.StXClass && ins.OpCode.Mode() == asm.MemMode:
			at, w := int(ins.Offset), width(ins)
			if ins.Dst != asm.RFP || at < stackBottom || at+w > f {
				return reject(StoreBounds, "inserted store outside reserved frame")
			}
			if err := read(ins.Src); err != nil {
				return err
			}
			result := at == f+slotResult && ins.Src == asm.R0 && w == 8 && (i == 0 || i == 1 && is[0].OpCode.Class() == asm.LdXClass)
			copyPair := isLookup && s.calls == 0 && i > 0 && ins.Src == asm.R1 && at+w <= f+slotMap && same(is[i-1], asm.LoadMem(asm.R1, asm.R0, is[i-1].Offset, ins.OpCode.Size())) && is[i-1].Offset >= 0
			if !result && !copyPair {
				return reject(StoreShape, "store is not result spill or lookup value copy")
			}
			s.store(at, w, s.regs[ins.Src])
		case cl == asm.LdXClass && ins.OpCode.Mode() == asm.MemMode:
			if ins.Dst > asm.R5 {
				return reject(LoadClobber, "inserted load clobbers R%d", ins.Dst)
			}
			if ins.Dst == asm.R0 && i != len(is)-1 {
				return reject(ResultLoad, "R0 load outside final restore")
			}
			if ins.Src == asm.RFP {
				cell, ok := s.stack[int(ins.Offset)]
				if !ok || cell.width != width(ins) {
					return reject(SpillUninitialized, "load from uninitialized/nonmatching spill %d", ins.Offset)
				}
				s.regs[ins.Dst] = cell.v
			} else {
				if !isLookup || s.calls != 0 || ins.Src != asm.R0 || ins.Dst != asm.R1 || ins.Offset < 0 || i+1 >= len(is) || is[i+1].OpCode.Class() != asm.StXClass {
					return reject(CopyShape, "non-stack load is not lookup value copy")
				}
				if err := read(ins.Src); err != nil {
					return err
				}
				s.regs[ins.Dst] = value{id: idOpaque}
			}
		case cl == asm.ALUClass || cl == asm.ALU64Class:
			if ins.Dst == asm.R0 || ins.Dst > asm.R5 {
				return reject(ALUClobber, "inserted ALU clobbers R%d", ins.Dst)
			}
			if ins.Offset != 0 {
				return reject(ALUEncoding, "unsupported ALU encoding")
			}
			op := ins.OpCode.ALUOp()
			src := value{id: idOpaque}
			if ins.OpCode.Source() == asm.RegSource {
				if err := read(ins.Src); err != nil {
					return err
				}
				src = s.regs[ins.Src]
			}
			if op != asm.Mov {
				if err := read(ins.Dst); err != nil {
					return err
				}
			}
			switch op {
			case asm.Mov:
				s.regs[ins.Dst] = src
				if cl == asm.ALUClass {
					s.regs[ins.Dst] = value{id: idOpaque}
				}
			case asm.Add:
				if cl != asm.ALU64Class || ins.OpCode.Source() != asm.ImmSource || !s.regs[ins.Dst].frame || ins.Constant < stackBottom || ins.Constant >= int64(f) {
					return reject(PointerCalculation, "not a reserved-frame pointer calculation")
				}
				v := s.regs[ins.Dst]
				v.ptr += int(ins.Constant)
				if v.ptr < stackBottom || v.ptr >= f {
					return reject(PointerBounds, "frame pointer outside reserved stack")
				}
				s.regs[ins.Dst] = v
			case asm.And, asm.LSh, asm.Or:
				s.regs[ins.Dst] = value{id: idOpaque}
			default:
				return reject(ALUOperation, "ALU operation %s outside helper observation", op)
			}
		case ins.IsFunctionCall():
			if err := hookCall(out, pcs, idx, js[i], hooks); err != nil {
				return err
			}
			s.calls++
			if s.calls > 1 {
				return reject(MultipleCalls, "multiple hooks on one site path")
			}
			for r := 0; r <= 5; r++ {
				s.regs[r] = value{}
			}
			s.regs[0] = value{id: idOpaque}
		case cl.IsJump() && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit:
			op := ins.OpCode.JumpOp()
			if ins.Reference() != "" || ins.Offset < 0 {
				return reject(BranchForward, "non-forward postlude branch")
			}
			j := i + 1 + int(ins.Offset)
			if j > len(is) {
				return reject(BranchEscape, "branch escapes site postlude")
			}
			if op == asm.Ja && (cl != asm.JumpClass || ins.Constant != 0 || ins.Dst != 0 || ins.Src != 0) {
				return reject(BranchEncoding, "noncanonical site jump")
			}
			if op != asm.Ja {
				allowed := isLookup && cl == asm.JumpClass && (op == asm.JEq || op == asm.JNE) || !isLookup && cl == asm.Jump32Class && op == asm.JSGE
				if tail || ins.Dst != asm.R0 || ins.Constant != 0 || ins.OpCode.Source() != asm.ImmSource || !allowed {
					return reject(BranchGuard, "branch not a helper result guard")
				}
				if err := read(asm.R0); err != nil {
					return err
				}
				if err := walk(i+1, s.clone()); err != nil {
					return err
				}
			}
			return walk(j, s)
		default:
			return reject(PostludeInstruction, "instruction outside helper observation: %v", ins)
		}
		return walk(i+1, s)
	}
	return walk(0, s)
}

func checkU32(load asm.Instruction, is, out asm.Instructions, pcs []int, idx map[int]int, js []int, hooks map[int]bool, f int, live uint16) error {
	if !same(load, asm.LoadMem(asm.R2, asm.R0, load.Offset, asm.Word)) {
		return reject(U32Placement, "insertion is not at a u32 load")
	}
	if live&u32Clobbers != 0 {
		return reject(U32Live, "u32 clobbers live registers mask %#x", live&u32Clobbers)
	}
	if f+slotKey < stackBottom || len(is) != 6 {
		return reject(U32Length, "not a six-instruction u32 region")
	}
	want := asm.Instructions{asm.StoreMem(asm.RFP, int16(f+slotContext), asm.R0, asm.DWord), asm.StoreMem(asm.RFP, int16(f+slotKey), asm.R2, asm.DWord), asm.Mov.Imm32(asm.R1, int32(is[2].Constant)), is[3], asm.LoadMem(asm.R0, asm.RFP, int16(f+slotContext), asm.DWord), asm.LoadMem(asm.R2, asm.RFP, int16(f+slotKey), asm.DWord)}
	if !equal(is, want) {
		return reject(U32Shape, "not a u32 save/call/restore sequence")
	}
	if err := hookCall(out, pcs, idx, js[3], hooks); err != nil {
		return err
	}
	start, err := target(out, pcs, idx, js[3])
	if err != nil {
		return err
	}
	if start+3 > len(out) || !isU32Hook(out[start:start+3]) {
		return reject(U32Hook, "u32 call does not target a u32 hook")
	}
	return nil
}

// liveness computes a conservative fixed point on the original CFG. Known
// helpers use their arity; BPF calls use callee live-in; unknown helpers and
// kfuncs read all argument registers.
func liveness(in asm.Instructions, pcs []int, idx map[int]int) ([]uint16, error) {
	n := len(in)
	live := make([]uint16, n+1)
	reads := make([]uint16, n)
	writes := make([]uint16, n)
	succ := make([][]int, n)
	bit := func(r asm.Register) uint16 {
		if r > asm.RFP {
			return allRegs
		}
		return 1 << r
	}
	for i, ins := range in {
		cl := ins.OpCode.Class()
		r, w := uint16(0), uint16(0)
		switch cl {
		case asm.ALUClass, asm.ALU64Class:
			w = bit(ins.Dst)
			if ins.OpCode.ALUOp() != asm.Mov {
				r |= bit(ins.Dst)
			}
			if ins.OpCode.Source() == asm.RegSource {
				r |= bit(ins.Src)
			}
		case asm.LdXClass:
			r = bit(ins.Src)
			w = bit(ins.Dst)
		case asm.LdClass:
			if ins.OpCode.Mode() != asm.ImmMode {
				r = allRegs
			}
			w = bit(ins.Dst)
		case asm.StClass:
			r = bit(ins.Dst)
		case asm.StXClass:
			r = bit(ins.Dst) | bit(ins.Src)
		case asm.JumpClass, asm.Jump32Class:
			switch ins.OpCode.JumpOp() {
			case asm.Call:
				r = argRegs
				w = callerSaved
				if ins.IsBuiltinCall() {
					r = helperReads(ins.Constant)
				}
			case asm.Exit:
				r = resultRegs
			case asm.Ja:
			default:
				r = bit(ins.Dst)
				if ins.OpCode.Source() == asm.RegSource {
					r |= bit(ins.Src)
				}
			}
		default:
			r = allRegs
		}
		reads[i], writes[i] = r, w
		if cl.IsJump() && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit {
			j, e := target(in, pcs, idx, i)
			if e != nil {
				return nil, e
			}
			succ[i] = append(succ[i], j)
		}
		if !cl.IsJump() || ins.OpCode.JumpOp() != asm.Ja && ins.OpCode.JumpOp() != asm.Exit {
			succ[i] = append(succ[i], i+1)
		}
	}
	for change := true; change; {
		change = false
		for i := n - 1; i >= 0; i-- {
			after := uint16(0)
			for _, j := range succ[i] {
				after |= live[j]
			}
			r := reads[i]
			if in[i].IsFunctionCall() {
				j, e := target(in, pcs, idx, i)
				if e != nil {
					return nil, e
				}
				r = live[j] & argRegs
			}
			v := r | after&^writes[i]
			if v != live[i] {
				live[i] = v
				change = true
			}
		}
	}
	// Check consumes liveness at the lexical continuation, which is precisely
	// where helper/u32 postludes return. The final sentinel has no live registers.
	return live, nil
}
