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
	depth    int // see stackCallGraph
	tailCall bool
	changed  bool  // new in the transform, or deeper than in the original
	callees  []int // deduplicated
}

// stackCallGraph splits insns into functions at BTF function metadata and
// links them by bpf-to-bpf calls and callback references, symbolic or
// numeric. Function 0 is the entry.
//
// A function's depth is its deepest direct R10 reference (R10 as the base of
// a load or store). A function that uses R10 in any other way, such as
// R2 = R10, can reach deeper through the copy, which the audited bound lowest
// covers by contract, so its depth is at least -lowest.
func stackCallGraph(insns asm.Instructions, lowest int16) ([]stackFunc, error) {
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
	aliased := make([]bool, len(funcs))
	cur := 0
	it = insns.Iterate()
	for it.Next() {
		pc, ins := int(it.Offset), it.Ins
		if i, ok := byStart[pc]; ok {
			cur = i
		}
		f := &funcs[cur]
		class := ins.OpCode.Class()
		load, store := class == asm.LdXClass, class == asm.StClass || class == asm.StXClass
		if ((load && ins.Src == asm.RFP) || (store && ins.Dst == asm.RFP)) && ins.Offset < 0 && int(-ins.Offset) > f.depth {
			f.depth = int(-ins.Offset)
		}
		if (ins.Src == asm.RFP && !load) || (ins.Dst == asm.RFP && !store) {
			aliased[cur] = true
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
	for i := range funcs {
		if aliased[i] {
			funcs[i].depth = max(funcs[i].depth, -int(lowest))
		}
	}
	return funcs, nil
}

// stackLimitBroken describes a limit that a changed chain of funcs breaks
// under round, or returns "". A chain is changed when it passes through a
// changed function; for the caller-depth limit, through a changed caller of
// the tail-calling function. Of the chains to a function it takes the longest
// changed one: the most caller bytes for the stack limits, the most frames for
// the frame limit. Callbacks count as synchronous frames under their
// referencing function, and functions no chain reaches (an exception
// callback, say) are walked as their own roots; both only make a chain longer
// than the kernel's walk.
func stackLimitBroken(funcs []stackFunc, round func(int) int) (string, error) {
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
			return "", err
		}
	}
	// above and frames are the most caller bytes and frames over every chain
	// to a function; aboveNew and framesNew over the chains with a changed
	// caller (-1 and 0 when there is none). The preds rebuild those chains.
	n := len(funcs)
	above, frames, aboveNew, framesNew := make([]int, n), make([]int, n), make([]int, n), make([]int, n)
	abovePred, framesPred, aboveNewPred, framesNewPred := make([]int, n), make([]int, n), make([]int, n), make([]int, n)
	for i := range funcs {
		frames[i], aboveNew[i] = 1, -1
		abovePred[i], framesPred[i], aboveNewPred[i], framesNewPred[i] = -1, -1, -1, -1
	}
	for k := len(order) - 1; k >= 0; k-- {
		i := order[k]
		f := funcs[i]
		// What i hands its callees over changed chains: every chain once i
		// itself changed.
		passAbove, passFrames := aboveNew[i], framesNew[i]
		if f.changed {
			passAbove, passFrames = above[i], frames[i]
		}
		for _, c := range f.callees {
			if sum := above[i] + round(f.depth); sum > above[c] {
				above[c], abovePred[c] = sum, i
			}
			if frames[i]+1 > frames[c] {
				frames[c], framesPred[c] = frames[i]+1, i
			}
			if sum := passAbove + round(f.depth); passAbove >= 0 && sum > aboveNew[c] {
				aboveNew[c], aboveNewPred[c] = sum, i
			}
			if passFrames > 0 && passFrames+1 > framesNew[c] {
				framesNew[c], framesNewPred[c] = passFrames+1, i
			}
		}
	}
	// chain names the chain to i whose last caller is j: the longest changed
	// chain up to its first changed function (from i itself when useAll), the
	// longest chain of any kind above that.
	chain := func(i, j int, useAll bool, all, changed []int) string {
		names := []string{funcs[i].name}
		for j >= 0 {
			names = append([]string{funcs[j].name}, names...)
			if useAll = useAll || funcs[j].changed; useAll {
				j = all[j]
			} else {
				j = changed[j]
			}
		}
		return strings.Join(names, " -> ")
	}
	broken := map[string]string{}
	for i, f := range funcs {
		if i != 0 && f.tailCall && aboveNew[i] >= maxCallerDepth {
			broken["caller:"+f.name] = fmt.Sprintf("the frames calling %s (%s) total %d bytes, at or past the kernel's %d-byte caller-depth limit for a subprogram that calls bpf_tail_call",
				f.name, chain(i, aboveNewPred[i], false, abovePred, aboveNewPred), aboveNew[i], maxCallerDepth)
		}
		callers, pred := aboveNew[i], aboveNewPred[i]
		if f.changed {
			callers, pred = above[i], abovePred[i]
		}
		if total := callers + round(f.depth); callers >= 0 && total > maxCombinedStack {
			broken["combined:"+f.name] = fmt.Sprintf("the call chain %s uses %d bytes of stack, past the kernel's %d-byte combined limit",
				chain(i, pred, f.changed, abovePred, aboveNewPred), total, maxCombinedStack)
		}
		count, fpred := framesNew[i], framesNewPred[i]
		if f.changed {
			count, fpred = frames[i], framesPred[i]
		}
		if count > maxCallFrames {
			broken["frames:"+f.name] = fmt.Sprintf("the call chain %s is %d frames deep, past the kernel's %d-frame limit",
				chain(i, fpred, f.changed, framesPred, framesNewPred), count, maxCallFrames)
		}
	}
	if len(broken) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(broken))
	for key := range broken {
		keys = append(keys, key)
	}
	sort.Strings(keys) // report the same limit on every run
	return broken[keys[0]], nil
}

// checkStackLimits refuses when out, the transformed program, breaks one of
// check_max_stack_depth's limits on a call chain the transform made deeper.
// The transform deepens frames to its spill slots and adds its hooks as frames
// called from each function holding a site, so a program the kernel accepted
// can cross the caller-depth limit of a tail-calling subprogram, the combined
// 512-byte stack, or the 8-frame call depth.
//
// Depths come from instructions, not from the verifier's walk, so they can
// overstate what the kernel counts: a store behind a branch the verifier
// never takes still deepens its function. An original chain past a limit is
// therefore no evidence that the kernel tolerates it, and only a chain the
// transform left unchanged may stay past a limit. A function is changed when
// it is new (a hook) or reaches deeper than in the original; the transform's
// slots lie below the audited bound, which every original direct reference
// respects (checkStackBound), so any slot it places in a function counts.
// Each limit is checked under each kernel frame rounding. lowest is the
// audited bound, the depth of a function that copies R10 (see stackCallGraph).
//
// The model is conservative in two known ways, both of which only refuse a
// program the kernel would load, never accept one it rejects: an async
// callback (bpf_timer_set_callback, bpf_wq_set_callback) is walked as part of
// the chain that references it, although 6.8 and later check it as a chain of
// its own; and 7.1 and later restart the frame count at a global function,
// which the frame limit here does not.
func checkStackLimits(in, out asm.Instructions, lowest int16) error {
	before, err := stackCallGraph(in, lowest)
	if err != nil {
		return err
	}
	after, err := stackCallGraph(out, lowest)
	if err != nil {
		return err
	}
	depth := map[string]int{}
	for _, f := range before {
		if _, dup := depth[f.name]; dup {
			depth[f.name] = -1 // ambiguous: every match counts as changed
			continue
		}
		depth[f.name] = f.depth
	}
	for i := range after {
		d, ok := depth[after[i].name]
		after[i].changed = !ok || d < 0 || after[i].depth > d
	}
	for _, r := range frameRoundings {
		broken, err := stackLimitBroken(after, r.round)
		if err != nil {
			return err
		}
		if broken != "" {
			return refuse("after the transform %s (frames rounded to %s bytes)", broken, r.name)
		}
	}
	return nil
}
