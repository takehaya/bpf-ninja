package inject

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Limits of the kernel's check_max_stack_depth (kernel/bpf/verifier.c), which
// walks every call chain from the entry through bpf-to-bpf calls and callback
// references (BPF_PSEUDO_FUNC loads):
//   - a subprogram other than the entry that calls bpf_tail_call must be
//     entered with less than maxCallerDepth bytes of caller frames,
//   - the frames along a chain may total at most maxCombinedStack bytes,
//   - a chain may hold at most maxCallFrames functions, the entry included.
const (
	maxCallerDepth   = 256
	maxCombinedStack = 512 // MAX_BPF_STACK
	maxCallFrames    = 8   // MAX_CALL_FRAMES
)

// frameRounding is how a kernel rounds each frame's stack depth before
// summing: up to 32 bytes, and at least 32, for the interpreter and on every
// 6.1 kernel; up to 16 bytes when newer kernels JIT the program
// (round_up_stack_depth). A program must pass under whichever its kernel uses.
type frameRounding struct {
	name  string
	round func(int) int
}

var frameRoundings = []frameRounding{
	{"32", func(n int) int { return (max(n, 1) + 31) / 32 * 32 }},
	{"16", func(n int) int { return (n + 15) / 16 * 16 }},
}

// stackFunc is one function of a program's call graph.
type stackFunc struct {
	name     string
	depth    int // deepest direct R10 reference, in bytes
	tailCall bool
	callees  []int // deduplicated
}

// stackCallGraph splits insns into functions at BTF function metadata and
// links them by bpf-to-bpf calls and callback references, symbolic or
// numeric. Function 0 is the entry.
func stackCallGraph(insns asm.Instructions) ([]stackFunc, error) {
	var funcs []stackFunc
	byStart, bySymbol := map[int]int{}, map[string]int{}
	it := insns.Iterate()
	for it.Next() {
		if fn := btf.FuncMetadata(it.Ins); fn != nil || it.Offset == 0 {
			name := it.Ins.Symbol()
			if fn != nil {
				name = fn.Name
			}
			byStart[int(it.Offset)] = len(funcs)
			if sym := it.Ins.Symbol(); sym != "" {
				bySymbol[sym] = len(funcs)
			}
			funcs = append(funcs, stackFunc{name: name})
		}
	}
	edges := make([]map[int]bool, len(funcs))
	cur := 0
	it = insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if i, ok := byStart[pc]; ok {
			cur = i
		}
		f := &funcs[cur]
		class := ins.OpCode.Class()
		if (class.IsLoad() || class.IsStore()) && (ins.Dst == asm.RFP || ins.Src == asm.RFP) && ins.Offset < 0 && int(-ins.Offset) > f.depth {
			f.depth = int(-ins.Offset)
		}
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
			f.tailCall = true
		}
		if !ins.IsFunctionCall() && !ins.IsLoadOfFunctionPointer() {
			continue
		}
		var target int
		var ok bool
		if ref := ins.Reference(); ref != "" {
			target, ok = bySymbol[ref]
		} else {
			target, ok = byStart[pc+1+int(ins.Constant)]
		}
		if !ok {
			return nil, refuse("function reference at %d does not target a subprogram", pc)
		}
		if edges[cur] == nil {
			edges[cur] = map[int]bool{}
		}
		if !edges[cur][target] {
			edges[cur][target] = true
			f.callees = append(f.callees, target)
		}
	}
	return funcs, nil
}

// stackLimitsExceeded returns, keyed by the limit and the function where it is
// reached, a description of every limit funcs exceed under round. Each value
// is the longest chain to that function: the most caller bytes for the stack
// limits, the most frames for the frame limit. Callbacks count as synchronous
// frames under their referencing function, and functions no chain reaches
// (an exception callback, say) are walked as their own roots; both only make
// a chain longer than the kernel's walk.
func stackLimitsExceeded(funcs []stackFunc, round func(int) int) (map[string]string, error) {
	// Topological order by depth-first postorder; a cycle is recursion, which
	// the kernel rejects.
	const (
		open = iota + 1
		done
	)
	state := make([]int, len(funcs))
	var order []int
	var visit func(i int) error
	visit = func(i int) error {
		switch state[i] {
		case open:
			return refuse("recursive call through %s", funcs[i].name)
		case done:
			return nil
		}
		state[i] = open
		for _, c := range funcs[i].callees {
			if err := visit(c); err != nil {
				return err
			}
		}
		state[i] = done
		order = append(order, i)
		return nil
	}
	for i := range funcs {
		if err := visit(i); err != nil {
			return nil, err
		}
	}
	// above is the most caller bytes on a chain to a function, frames the
	// most frames on a chain through it; the preds rebuild those chains.
	above, frames := make([]int, len(funcs)), make([]int, len(funcs))
	abovePred, framesPred := make([]int, len(funcs)), make([]int, len(funcs))
	for i := range funcs {
		frames[i], abovePred[i], framesPred[i] = 1, -1, -1
	}
	for k := len(order) - 1; k >= 0; k-- {
		i := order[k]
		for _, c := range funcs[i].callees {
			if sum := above[i] + round(funcs[i].depth); sum > above[c] {
				above[c], abovePred[c] = sum, i
			}
			if frames[i]+1 > frames[c] {
				frames[c], framesPred[c] = frames[i]+1, i
			}
		}
	}
	chain := func(i int, pred []int) string {
		var names []string
		for ; i >= 0; i = pred[i] {
			names = append([]string{funcs[i].name}, names...)
		}
		return strings.Join(names, " -> ")
	}
	exceeded := map[string]string{}
	for i, f := range funcs {
		if i != 0 && f.tailCall && above[i] >= maxCallerDepth {
			exceeded["caller:"+f.name] = fmt.Sprintf("the frames calling %s (%s) total %d bytes, at or past the kernel's %d-byte caller-depth limit for a subprogram that calls bpf_tail_call",
				f.name, chain(i, abovePred), above[i], maxCallerDepth)
		}
		if total := above[i] + round(f.depth); total > maxCombinedStack {
			exceeded["combined:"+f.name] = fmt.Sprintf("the call chain %s uses %d bytes of stack, past the kernel's %d-byte combined limit",
				chain(i, abovePred), total, maxCombinedStack)
		}
		if frames[i] > maxCallFrames {
			exceeded["frames:"+f.name] = fmt.Sprintf("the call chain %s is %d frames deep, past the kernel's %d-frame limit",
				chain(i, framesPred), frames[i], maxCallFrames)
		}
	}
	return exceeded, nil
}

// checkStackLimits refuses when out, the transformed program, reaches one of
// check_max_stack_depth's limits that the original program in does not. The
// transform deepens frames to its spill slots and adds its hooks as frames
// called from each function holding a site, so a program the kernel accepted
// can cross the caller-depth limit of a tail-calling subprogram, the combined
// 512-byte stack, or the 8-frame call depth. Both programs are measured the
// same way, under each kernel frame rounding, and a limit the original
// already reaches is left to the kernel. A function's depth is its deepest
// direct R10 reference, the bound checkStackBound trusts: stack reached only
// through an alias or a helper argument is the stack audit's to cover.
func checkStackLimits(in, out asm.Instructions) error {
	before, err := stackCallGraph(in)
	if err != nil {
		return err
	}
	after, err := stackCallGraph(out)
	if err != nil {
		return err
	}
	for _, r := range frameRoundings {
		was, err := stackLimitsExceeded(before, r.round)
		if err != nil {
			return err
		}
		now, err := stackLimitsExceeded(after, r.round)
		if err != nil {
			return err
		}
		var keys []string
		for key := range now {
			if _, ok := was[key]; !ok {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			continue
		}
		sort.Strings(keys) // report the same limit on every run
		return refuse("after the transform %s (frames rounded to %s bytes)", now[keys[0]], r.name)
	}
	return nil
}
