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
// The 32-byte rounding is never smaller than the 16-byte one, and every limit
// only grows with the rounded depths, so the "16" pass never reports a chain
// the "32" pass accepted. It stays to document what JITing kernels count.
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

// stackTopoOrder lists funcs callers first. A cycle is recursion, which the
// kernel rejects.
func stackTopoOrder(funcs []stackFunc) ([]int, error) {
	const (
		open = iota + 1
		done
	)
	state := make([]int, len(funcs))
	var postorder []int
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
		postorder = append(postorder, i)
		return nil
	}
	for i := range funcs {
		if err := visit(i); err != nil {
			return nil, err
		}
	}
	for i, j := 0, len(postorder)-1; i < j; i, j = i+1, j-1 {
		postorder[i], postorder[j] = postorder[j], postorder[i]
	}
	return postorder, nil
}

// A chainKind selects the call chains to a function that a limit is measured
// over.
type chainKind int

const (
	anyChain     chainKind = iota // every chain
	changedChain                  // the chains through a changed caller
)

// callerChain is one chain of callers above a function: their rounded frame
// bytes and count, the direct caller the chain ends with (-1 at a root), and
// which of that caller's own chains it extends.
type callerChain struct {
	bytes, frames int
	caller        int
	from          chainKind
}

// callerChains are the longest chains of callers above a function, by bytes
// and by frames (the two can differ), or none when found is false.
type callerChains struct {
	found    bool
	byBytes  callerChain
	byFrames callerChain
}

// extend adds caller, whose frame holds bytes, to from's chains and keeps
// whichever is longer. Ties keep the earlier caller.
func (cc *callerChains) extend(from callerChains, kind chainKind, caller, bytes int) {
	if !from.found {
		return
	}
	grow := func(c callerChain) callerChain {
		return callerChain{bytes: c.bytes + bytes, frames: c.frames + 1, caller: caller, from: kind}
	}
	if c := grow(from.byBytes); !cc.found || c.bytes > cc.byBytes.bytes {
		cc.byBytes = c
	}
	if c := grow(from.byFrames); !cc.found || c.frames > cc.byFrames.frames {
		cc.byFrames = c
	}
	cc.found = true
}

// stackReach is what the longest chains reach at each function of a call
// graph: reach[i][anyChain] over every chain to i, reach[i][changedChain]
// over the chains through a changed caller of i.
type stackReach struct {
	funcs []stackFunc
	reach [][2]callerChains
}

// stackChains measures funcs' call chains with each frame rounded by round.
// Callbacks count as frames under their referencing function, and a function
// no chain reaches (an exception callback, say) starts a chain of its own.
func stackChains(funcs []stackFunc, round func(int) int) (*stackReach, error) {
	order, err := stackTopoOrder(funcs)
	if err != nil {
		return nil, err
	}
	s := &stackReach{funcs: funcs, reach: make([][2]callerChains, len(funcs))}
	for i := range funcs {
		s.reach[i][anyChain] = callerChains{found: true, byBytes: callerChain{caller: -1}, byFrames: callerChain{caller: -1}}
	}
	for _, i := range order {
		f := funcs[i]
		// Below a changed function every chain counts as changed.
		pass := changedChain
		if f.changed {
			pass = anyChain
		}
		for _, c := range f.callees {
			s.reach[c][anyChain].extend(s.reach[i][anyChain], anyChain, i, round(f.depth))
			s.reach[c][changedChain].extend(s.reach[i][pass], pass, i, round(f.depth))
		}
	}
	return s, nil
}

// counted returns the chains to i that a changed chain through i is measured
// over: every chain when i itself changed, else those with a changed caller.
func (s *stackReach) counted(i int) callerChains {
	if s.funcs[i].changed {
		return s.reach[i][anyChain]
	}
	return s.reach[i][changedChain]
}

// names spells out the chain c leads to i along, root first.
func (s *stackReach) names(i int, c callerChain, byFrames bool) string {
	names := []string{s.funcs[i].name}
	for c.caller >= 0 {
		names = append([]string{s.funcs[c.caller].name}, names...)
		if next := s.reach[c.caller][c.from]; byFrames {
			c = next.byFrames
		} else {
			c = next.byBytes
		}
	}
	return strings.Join(names, " -> ")
}

// stackLimitBroken describes a limit that a changed chain of funcs breaks
// under round, or returns "". A chain is changed when it passes through a
// changed function; for the caller-depth limit, through a changed caller of
// the tail-calling function. Of the chains to a function it takes the longest
// changed one: the most caller bytes for the stack limits, the most frames for
// the frame limit.
func stackLimitBroken(funcs []stackFunc, round func(int) int) (string, error) {
	s, err := stackChains(funcs, round)
	if err != nil {
		return "", err
	}
	broken := map[string]string{}
	for i, f := range funcs {
		if callers := s.reach[i][changedChain]; i != 0 && f.tailCall && callers.found && callers.byBytes.bytes >= maxCallerDepth {
			broken["caller:"+f.name] = fmt.Sprintf("the frames calling %s (%s) total %d bytes, at or past the kernel's %d-byte caller-depth limit for a subprogram that calls bpf_tail_call",
				f.name, s.names(i, callers.byBytes, false), callers.byBytes.bytes, maxCallerDepth)
		}
		counted := s.counted(i)
		if !counted.found {
			continue
		}
		if total := counted.byBytes.bytes + round(f.depth); total > maxCombinedStack {
			broken["combined:"+f.name] = fmt.Sprintf("the call chain %s uses %d bytes of stack, past the kernel's %d-byte combined limit",
				s.names(i, counted.byBytes, false), total, maxCombinedStack)
		}
		if count := counted.byFrames.frames + 1; count > maxCallFrames {
			broken["frames:"+f.name] = fmt.Sprintf("the call chain %s is %d frames deep, past the kernel's %d-frame limit",
				s.names(i, counted.byFrames, true), count, maxCallFrames)
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
//
// The split into changed and unchanged chains matters only where an original
// chain can stay unchanged: in the single-site Transform, and for an
// exception callback or other root no chain from the entry reaches. The
// lookup transform always deepens the entry (its ctx spill lies below the
// audited bound), so every chain from the entry counts as changed.
func checkStackLimits(in, out asm.Instructions, lowest int16) error {
	broken, err := stackLimitsBroken(in, out, lowest)
	if err != nil {
		return err
	}
	if broken != "" {
		return refuse("%s", broken)
	}
	return nil
}

// stackLimitsBroken is checkStackLimits' limit description without the
// ErrRefused prefix, or "" when out keeps every limit; Auto uses it as a
// skip reason.
func stackLimitsBroken(in, out asm.Instructions, lowest int16) (string, error) {
	before, err := stackCallGraph(in, lowest)
	if err != nil {
		return "", err
	}
	after, err := stackCallGraph(out, lowest)
	if err != nil {
		return "", err
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
			return "", err
		}
		if broken != "" {
			return fmt.Sprintf("after the transform %s (frames rounded to %s bytes)", broken, r.name), nil
		}
	}
	return "", nil
}
