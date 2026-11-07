// Package injectcheck independently checks the instruction-level safety of an
// injection. It does not import the transformer. A certificate supplies only
// correspondence hints: every hint and every otherwise unaccounted bytecode
// instruction is checked. Acceptance is conditional on the original and
// transformed programs being valid BPF, the BPF calling convention, and the
// caller's trusted stack-alias audit and plan-derived site targets.
package injectcheck

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
)

// Span is a half-open range of decoded instruction indices, not raw slots.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// TargetWhen is the planned helper result on which a hook runs.
type TargetWhen string

const (
	TargetHit     TargetWhen = "hit"
	TargetMiss    TargetWhen = "miss"
	TargetAny     TargetWhen = "any"
	TargetError   TargetWhen = "error"
	targetSuccess TargetWhen = "success"
)

// SiteTarget binds one original helper site and result arm to a planned hook.
// Site -1 is the entry hook. Args is the planned hook's argument list from R1
// on for a lookup site, one of the lookupABIs; SitePC is the immediate its
// ArgSite argument carries. A wrapped site needs Args. Elsewhere nil Args
// leaves the arguments to the provenance rules alone.
type SiteTarget struct {
	Site   int        `json:"site"`
	When   TargetWhen `json:"when"`
	Hook   int        `json:"hook"` // Decoded instruction index of the hook start.
	Ctx    *CtxSource `json:"ctx,omitempty"`
	Args   []ArgRole  `json:"args,omitempty"`
	SitePC int32      `json:"site_pc,omitempty"`
}

// ArgRole is what one hook argument holds.
type ArgRole string

const (
	ArgCtx   ArgRole = "ctx"
	ArgSite  ArgRole = "site"  // SiteTarget.SitePC
	ArgKey   ArgRole = "key"   // the helper's R2
	ArgValue ArgRole = "value" // the helper's R0; unwrapped, any stack pointer below the map slot
	ArgMap   ArgRole = "map"   // the helper's R1
)

// lookupABIs are the argument lists a lookup hook can have: typed without
// and with the site, a typed miss without the value, and generic.
var lookupABIs = [][]ArgRole{
	{ArgCtx, ArgKey, ArgValue},
	{ArgCtx, ArgKey},
	{ArgCtx, ArgSite, ArgKey, ArgValue},
	{ArgCtx, ArgSite, ArgKey},
	{ArgCtx, ArgSite, ArgKey, ArgValue, ArgMap},
}

// CtxSource is the plan-proved context value used to initialize a callee
// frame. Reg is R6-R9, or Slot is an aligned offset in the audited frame. For a
// synchronous callback, Param (R2 or R4) holds the entry frame's R10+Arg at the
// callback's entry, and the callback loads the entry's context slot through it.
// Pass is set when the context is passed down from the entry: Pass[0] is the
// site's function, and the rest the functions above it that pass it on.
type CtxSource struct {
	Reg   int         `json:"reg,omitempty"`
	Slot  int16       `json:"slot,omitempty"`
	Param int         `json:"param,omitempty"`
	Arg   int16       `json:"arg,omitempty"`
	Pass  []PassFrame `json:"pass,omitempty"`
}

// PassFrame is a function, at decoded original index Start, that stores Reg
// (R1-R5) into its context slot on entry. Unless Saved, Reg is a register the
// function never reads before writing it, and every direct call to it loads
// the context into Reg from the caller's slot right before the call. If Saved,
// Reg is the function's own context parameter; that rests on the
// transformer's proof, like Reg and Slot.
type PassFrame struct {
	Start int  `json:"start"`
	Reg   int  `json:"reg"`
	Saved bool `json:"saved,omitempty"`
}

func (c CtxSource) equal(o CtxSource) bool {
	return c.Reg == o.Reg && c.Slot == o.Slot && c.Param == o.Param && c.Arg == o.Arg && slices.Equal(c.Pass, o.Pass)
}

// Certificate is untrusted layout metadata. Original[i] locates original
// instruction i in the output; Hooks lists inserted functions. Wrappers lists
// inserted functions that hold a lookup helper (see checkWrapper).
type Certificate struct {
	Original []int  `json:"original"`
	Hooks    []Span `json:"hooks"`
	Wrappers []Span `json:"wrappers,omitempty"`
}

// Counts reports input size, checked sites and declared hook bodies.
// Sites is partial when Check returns an error.
type Counts struct {
	Instructions int `json:"instructions"`
	Sites        int `json:"sites"`
	Hooks        int `json:"hooks"`
}

// Premises contains trusted caller inputs: the stack audit and the target
// binding built from the rewrite plan, never from transformed call references.
type Premises struct {
	LowestOffset int16        `json:"lowest_offset"`
	Frames       []FrameFloor `json:"frames,omitempty"`
	Targets      []SiteTarget `json:"targets"`
}

// FrameFloor applies LowestOffset from Start until the next frame start.
// Start is a decoded instruction index in the original program.
type FrameFloor struct {
	Start        int   `json:"start"`
	LowestOffset int16 `json:"lowest_offset"`
}

type label struct{}

// Label adds correspondence hints before a transform that preserves metadata.
// These hints are never used as evidence that an instruction is unchanged.
func Label(in asm.Instructions) {
	for i := range in {
		in[i].Metadata.Set(label{}, i)
	}
}

// FromLabels extracts hints, including hook ranges supplied by the caller.
// Missing, repeated or forged labels are rejected here or by Check.
func FromLabels(out asm.Instructions, n int, hooks []Span) (Certificate, error) {
	c := Certificate{Original: make([]int, n), Hooks: hooks}
	for i := range c.Original {
		c.Original[i] = -1
	}
	for j, ins := range out {
		if i, ok := ins.Metadata.Get(label{}).(int); ok {
			if i < 0 || i >= n || c.Original[i] != -1 {
				return c, reject(LabelInvalid, "duplicate/invalid original label %d", i)
			}
			c.Original[i] = j
		}
	}
	return c, nil
}

func same(a, b asm.Instruction) bool {
	return a.OpCode == b.OpCode && a.Dst == b.Dst && a.Src == b.Src && a.Offset == b.Offset && a.Constant == b.Constant
}
func slots(in asm.Instructions) ([]int, map[int]int) {
	pcs := make([]int, len(in))
	index := make(map[int]int, len(in))
	pc := 0
	for i, ins := range in {
		pcs[i] = pc
		index[pc] = i
		pc += int(ins.Size() / asm.InstructionSize)
	}
	return pcs, index
}
func edge(ins asm.Instruction) bool {
	return ins.IsFunctionReference() || (ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit)
}
func target(in asm.Instructions, pcs []int, index map[int]int, i int) (int, error) {
	ins := in[i]
	if ref := ins.Reference(); ref != "" {
		if (ins.IsFunctionReference() && ins.Constant != -1) || (!ins.IsFunctionReference() && ins.Offset != -1) {
			return 0, reject(EdgeResolved, "already resolved symbolic edge at %d", i)
		}
		found := -1
		for j, x := range in {
			if x.Symbol() == ref {
				if found >= 0 {
					return 0, reject(SymbolAmbiguous, "ambiguous symbol %q", ref)
				}
				found = j
			}
		}
		if found < 0 {
			return 0, reject(SymbolUnresolved, "unresolved symbol %q", ref)
		}
		return found, nil
	}
	delta := int(ins.Offset)
	if ins.IsFunctionReference() || (ins.OpCode.Class() == asm.Jump32Class && ins.OpCode.JumpOp() == asm.Ja) {
		delta = int(ins.Constant)
	}
	j, ok := index[pcs[i]+1+delta]
	if !ok {
		return 0, reject(EdgeSlot, "edge at %d targets non-instruction slot %d", i, pcs[i]+1+delta)
	}
	return j, nil
}

// Check checks all original instructions, every explicit control-flow edge,
// all gaps and all hook bodies. Unknown forms fail closed. It never loads BPF.
// Associated maps are unsupported: callers must supply both streams before
// map association, with the same external symbol/FD bindings throughout.
func Check(in, out asm.Instructions, c Certificate, premises Premises) (Counts, error) {
	counts := Counts{Instructions: len(in), Hooks: len(c.Hooks)}
	fail := func(kind Kind, s string, args ...any) (Counts, error) { return counts, reject(kind, s, args...) }
	if len(in) == 0 {
		return counts, inputError(InputOriginalEmpty, "original must contain instructions")
	}
	// A jump table's targets are outside both streams, so no edge can be compared.
	for _, stream := range []asm.Instructions{in, out} {
		for i, ins := range stream {
			if ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() == asm.Ja && ins.OpCode.Source() == asm.RegSource {
				return fail(IndirectJump, "indirect jump at instruction %d", i)
			}
		}
	}
	if len(c.Original) == 0 {
		return counts, inputError(InputCertificateEmpty, "certificate.original must not be empty")
	}
	if len(c.Original) != len(in) {
		return counts, inputError(InputCertificateLength, "certificate.original length %d differs from original length %d", len(c.Original), len(in))
	}
	if premises.LowestOffset > 0 || premises.LowestOffset < stackBottom {
		return counts, inputError(InputStackFloor, "lowest_offset must be in [-512,0], got %d", premises.LowestOffset)
	}
	for i, frame := range premises.Frames {
		if frame.LowestOffset > 0 || frame.LowestOffset < stackBottom {
			return counts, inputError(InputStackFloor, "frames[%d].lowest_offset must be in [-512,0], got %d", i, frame.LowestOffset)
		}
		if frame.Start < 0 || frame.Start >= len(in) || i > 0 && frame.Start <= premises.Frames[i-1].Start {
			return counts, inputError(InputStackFloor, "frames must have increasing starts within the original program")
		}
	}
	if len(premises.Frames) != 0 && premises.Frames[0].Start != 0 {
		return counts, inputError(InputStackFloor, "frames must start at original instruction 0")
	}
	for i, a := range in {
		if a.Dst > asm.RFP || a.Src > asm.RFP {
			return counts, inputError(InputRegister, "original instruction %d: invalid register dst=%d src=%d", i, a.Dst, a.Src)
		}
	}
	if err := unassociated(in); err != nil {
		return counts, fmt.Errorf("original: %w", err)
	}
	if err := unassociated(out); err != nil {
		return counts, fmt.Errorf("transformed: %w", err)
	}
	lowestAt := func(i int) int {
		lowest := int(premises.LowestOffset)
		for _, frame := range premises.Frames {
			if frame.Start > i {
				break
			}
			lowest = int(frame.LowestOffset)
		}
		return lowest
	}
	floorAt := func(i int) int { return lowestAt(i) &^ 7 }
	owners := make([]int, len(out))
	for i := range owners {
		owners[i] = -1
	}
	prev := -1
	for i, j := range c.Original {
		if j <= prev || j >= len(out) {
			return counts, inputError(OriginalOrder, "original %d missing or out of order at %d", i, j)
		}
		owners[j] = i
		prev = j
	}
	hooks := map[int]bool{}
	for _, h := range c.Hooks {
		if h.Start < 0 || h.End <= h.Start || h.End > len(out) {
			return counts, inputError(HookRange, "invalid hook range %+v", h)
		}
		for j := h.Start; j < h.End; j++ {
			if owners[j] != -1 {
				return counts, inputError(HookOverlap, "overlapping hook at %d", j)
			}
			owners[j] = -2
		}
		if err := checkHook(out[h.Start:h.End]); err != nil {
			return counts, fmt.Errorf("hook %d: %w", h.Start, err)
		}
		hooks[h.Start] = true
	}
	wrappers := map[int]Span{}
	for _, w := range c.Wrappers {
		if w.Start < 0 || w.End <= w.Start || w.End > len(out) {
			return counts, inputError(HookRange, "invalid wrapper range %+v", w)
		}
		for j := w.Start; j < w.End; j++ {
			if owners[j] != -1 {
				return counts, inputError(HookOverlap, "overlapping wrapper at %d", j)
			}
			owners[j] = -2
		}
		wrappers[w.Start] = w
	}
	targets, err := newTargetBindings(premises.Targets, len(in), hooks)
	if err != nil {
		return counts, err
	}
	for j, owner := range owners {
		if owner < 0 {
			if err := noLoadMetadata(out[j]); err != nil {
				return counts, fmt.Errorf("transformed instruction %d: %w", j, err)
			}
		}
	}
	// Hook bodies were excluded above; reject any fall-through into one.
	for _, h := range slices.Concat(c.Hooks, c.Wrappers) {
		if h.Start == 0 || !terminal(out[h.Start-1]) {
			return fail(HookFallthrough, "fall-through into hook %d", h.Start)
		}
	}
	opcs, oi := slots(in)
	npcs, ni := slots(out)
	gaps := make([][]int, len(in)+1)
	k := 0
	for j, owner := range owners {
		if owner >= 0 {
			k = owner + 1
		} else if owner == -1 {
			gaps[k] = append(gaps[k], j)
		}
	}
	for _, g := range gaps {
		for j := 1; j < len(g); j++ {
			if g[j] != g[j-1]+1 {
				return fail(RegionSplit, "hook splits an insertion region")
			}
		}
	}
	gather := func(js []int) asm.Instructions {
		is := make(asm.Instructions, len(js))
		for i, j := range js {
			is[i] = out[j]
		}
		return is
	}
	callbacks, callbackOwner, err := callbackFrames(in, opcs, oi, targets, premises.Frames)
	if err != nil {
		return counts, err
	}
	for start, ctx := range callbacks {
		if int(ctx.Arg) < lowestAt(0) {
			return fail(CtxProvenance, "the callback at %d gets fp%d, below the entry floor %d", start, ctx.Arg, lowestAt(0))
		}
	}
	for site, start := range callbackOwner {
		if floorAt(site) != floorAt(start) {
			return fail(CtxProvenance, "callback site %d has floor %d, but the callback at %d stores the context below floor %d", site, floorAt(site), start, floorAt(start))
		}
	}
	passes, passOwner, err := passFrames(in, opcs, oi, targets, premises.Frames)
	if err != nil {
		return counts, err
	}
	for site, start := range passOwner {
		if floorAt(site) != floorAt(start) {
			return fail(CtxProvenance, "site %d has floor %d, but its function at %d stores the context below floor %d", site, floorAt(site), start, floorAt(start))
		}
	}
	functionStarts := map[int]int{}
	// A function the context is passed through stores it on entry. Each call
	// to one that takes it in a free register first loads it from the
	// caller's slot; a branch to the call lands on that load.
	passLoads := map[int]int{}
	for _, start := range slices.Sorted(maps.Keys(passes)) {
		pass := passes[start]
		g := gaps[start]
		if len(g) == 0 || !same(out[g[0]], asm.StoreMem(asm.RFP, int16(floorAt(start)+slotContext), asm.Register(pass.frame.Reg), asm.DWord)) || floorAt(start)+slotContext < stackBottom {
			return fail(CtxProvenance, "the function at %d does not start by storing r%d in its context slot", start, pass.frame.Reg)
		}
		functionStarts[start] = g[0]
		gaps[start] = g[1:]
	}
	for _, start := range slices.Sorted(maps.Keys(passes)) {
		pass := passes[start]
		for _, call := range pass.calls {
			from := floorAt(call.caller) + slotContext
			if call.caller == 0 && len(gaps[0]) == 0 {
				return fail(CtxProvenance, "the call at %d loads an entry context slot that is never spilled", call.at)
			}
			if floorAt(call.at) != floorAt(call.caller) {
				return fail(CtxProvenance, "the call at %d has floor %d, but its function at %d keeps the context below floor %d", call.at, floorAt(call.at), call.caller, floorAt(call.caller))
			}
			g := gaps[call.at]
			if len(g) == 0 || !same(out[g[len(g)-1]], asm.LoadMem(asm.Register(pass.frame.Reg), asm.RFP, int16(from), asm.DWord)) {
				return fail(CtxProvenance, "the call at %d to the function at %d does not load the context into r%d first", call.at, start, pass.frame.Reg)
			}
			passLoads[call.at] = g[len(g)-1]
			gaps[call.at] = g[:len(g)-1]
		}
	}
	for start, ctx := range callbacks {
		if len(gaps[0]) == 0 {
			return fail(CtxProvenance, "callback at %d reads an entry context slot that is never spilled", start)
		}
		g := gaps[start]
		want := asm.Instructions{
			asm.LoadMem(asm.R0, asm.Register(ctx.Param), int16(floorAt(0)+slotContext-int(ctx.Arg)), asm.DWord),
			asm.StoreMem(asm.RFP, int16(floorAt(start)+slotContext), asm.R0, asm.DWord),
		}
		if len(g) < len(want) || !equal(gather(g[:len(want)]), want) {
			return fail(CtxProvenance, "callback at %d does not start with the context load its premise names", start)
		}
		functionStarts[start] = g[0]
		gaps[start] = g[len(want):]
	}
	// A helper's prelude is the trailing sequence of stack spills before it.
	starts := slices.Clone(c.Original)
	before := make([]asm.Instructions, len(in))
	// A wrapped site is a lookup helper whose output is a call to a wrapper,
	// entered through the one instruction that loads ctx into R4.
	wrapped := map[int]Span{}
	calledWrappers := map[int]bool{}
	for i := range in {
		j := c.Original[i]
		if !out[j].IsFunctionCall() || in[i].IsFunctionCall() {
			continue
		}
		t, e := target(out, npcs, ni, j)
		if e != nil {
			return counts, fmt.Errorf("transformed call: %w", e)
		}
		w, ok := wrappers[t]
		if !ok {
			continue
		}
		if calledWrappers[t] {
			return fail(WrapperCall, "wrapper %d called by two sites", t)
		}
		calledWrappers[t] = true
		wrapped[i] = w
		g := gaps[i]
		if len(g) == 0 {
			return fail(WrapperPrelude, "site %d loads no context for its wrapper", i)
		}
		starts[i] = g[len(g)-1]
		before[i] = asm.Instructions{out[g[len(g)-1]]}
		gaps[i] = g[:len(g)-1]
	}
	if len(calledWrappers) != len(wrappers) {
		return fail(WrapperCall, "a wrapper is not called by any site")
	}
	for i := range in {
		if !supportedHelper(in[i]) {
			continue
		}
		if _, ok := wrapped[i]; ok {
			continue
		}
		g := gaps[i]
		n := len(g)
		for n > 0 && stackSpill(out[g[n-1]]) {
			n--
		}
		ctx := siteCtx(targets, i)
		if n > 0 && ctx != nil && ctx.Slot != 0 && n < len(g) &&
			same(out[g[n-1]], asm.LoadMem(asm.R0, asm.RFP, ctx.Slot, asm.DWord)) {
			n--
			for n > 0 && stackSpill(out[g[n-1]]) {
				n--
			}
		}
		if n < len(g) {
			starts[i] = g[n]
			for _, j := range g[n:] {
				before[i] = append(before[i], out[j])
			}
			gaps[i] = g[:n]
			if err := checkBefore(in[i], before[i], floorAt(i), lowestAt(i), ctx); err != nil {
				return counts, fmt.Errorf("site %d prelude: %w", i, err)
			}
		}
	}
	// The one-time entry prologue is excluded from backward edges to original 0,
	// but a branch to a call that passes the context lands on its load.
	starts[0] = c.Original[0]
	for at, load := range passLoads {
		starts[at] = load
	}
	live, err := liveness(in, opcs, oi)
	if err != nil {
		return counts, inputError(InputOriginalCFG, "original CFG: %v", err)
	}
	// Function-referenced subprogram/callback entries delimit the entry frame.
	// The entry spill initializes only the entry frame, never a callee frame.
	entryEnd := len(in)
	for i, a := range in {
		b := out[c.Original[i]]
		if err := compareMetadata(a, b); err != nil {
			return counts, fmt.Errorf("original instruction %d: %w", i, err)
		}
		if _, ok := wrapped[i]; ok {
			continue // checkWrapper finds this instruction, unchanged, in the wrapper
		}
		aa, bb := a, b
		if edge(a) {
			t, e := target(in, opcs, oi, i)
			if e != nil {
				return counts, inputError(InputOriginalCFG, "original edge: %v", e)
			}
			if a.IsFunctionReference() {
				entryEnd = min(entryEnd, t)
			}
			if a.IsFunctionReference() && t == 0 {
				return counts, inputError(InputOriginalCFG, "original function reference targets entry")
			}
			u, e := target(out, npcs, ni, c.Original[i])
			if e != nil {
				return counts, fmt.Errorf("transformed edge: %w", e)
			}
			expected := starts[t]
			if head, ok := functionStarts[t]; ok && a.IsFunctionReference() {
				expected = head
			}
			if u != expected {
				return fail(EdgeTarget, "edge %d targets %d; expected %d (original %d)", i, u, expected, t)
			}
			if a.IsFunctionReference() {
				aa.Constant = 0
				bb.Constant = 0
			} else if a.OpCode.Class() == asm.Jump32Class && a.OpCode.JumpOp() == asm.Ja {
				aa.Constant = 0
				bb.Constant = 0
			} else {
				aa.Offset = 0
				bb.Offset = 0
			}
		} else if a.Reference() != b.Reference() {
			return fail(OriginalReference, "original %d reference changed", i)
		}
		if !same(aa, bb) {
			return fail(OriginalChanged, "original instruction %d changed: %s", i, differingFields(aa, bb))
		}
		if err := stackAudit(a, lowestAt(i)); err != nil {
			return counts, fmt.Errorf("original %d: %w", i, err)
		}
	}
	if len(gaps[0]) > 0 {
		if err := checkEntry(gather(gaps[0]), out, npcs, ni, gaps[0], hooks, targets, floorAt(0)); err != nil {
			return counts, fmt.Errorf("entry: %w", err)
		}
	}
	for i := range in {
		after := gather(gaps[i+1])
		if w, ok := wrapped[i]; ok {
			if len(after) != 0 {
				return fail(WrapperShape, "site %d has a postlude beside its wrapper", i)
			}
			if err := checkWrapperPrelude(before[i][0], targets.ctxForSite(i), lowestAt(i), floorAt(i), len(gaps[0]) > 0 && i < entryEnd); err != nil {
				return counts, fmt.Errorf("site %d: %w", i, err)
			}
			if err := checkWrapper(i, in[i], out, npcs, ni, w, hooks, targets); err != nil {
				return counts, fmt.Errorf("site %d wrapper: %w", i, err)
			}
			counts.Sites++
			continue
		}
		if len(before[i]) > 0 {
			if err := checkAfter(i, in[i], before[i], after, out, npcs, ni, gaps[i+1], hooks, targets,
				floorAt(i), len(gaps[0]) > 0 && i < entryEnd || callbackSite(targets, i), siteCtx(targets, i)); err != nil {
				return counts, fmt.Errorf("site %d: %w", i, err)
			}
			counts.Sites++
		} else if len(after) > 0 {
			// A u32 region saves R0 in its frame's context slot, which a
			// callback's prologue reads in the entry and fills in the callback.
			if len(callbacks) != 0 || len(passes) != 0 {
				return fail(CtxProvenance, "u32 region after %d may overwrite a context slot that a callback or a passed context reads or fills", i)
			}
			if err := checkU32(i, in[i], after, out, npcs, ni, gaps[i+1], hooks, targets, floorAt(i), live[i+1]); err != nil {
				return counts, fmt.Errorf("gap after %d: %w", i, err)
			}
			counts.Sites++
		}
	}
	if err := targets.checkUsed(); err != nil {
		return counts, err
	}
	return counts, nil
}

// siteCtx is the context a site's prelude initializes: none in a callback or
// a function the context is passed to, whose prologue did so already.
func siteCtx(targets targetBindings, site int) *CtxSource {
	if callbackSite(targets, site) {
		return nil
	}
	return targets.ctxForSite(site)
}

// callbackSite reports a site whose function's prologue fills its context slot.
func callbackSite(targets targetBindings, site int) bool {
	ctx := targets.ctxForSite(site)
	return ctx != nil && (ctx.Param != 0 || len(ctx.Pass) != 0)
}

// callbackFrames maps the start of each function holding a callback-context
// site to its premise, and each such site to that start, after re-deriving the
// premise from the original stream: the site is reachable from the start
// without a call, the function is never called directly, and every reference
// to it is reachable from instruction 0 and passes Param's helper R10+Arg,
// with no branch landing between `r3 = r10` and the helper call. Static
// linkage rests on the transformer's proof. With a callback, no frame floor
// may start inside the entry or a callback after its start, and an entry site
// may not name a context source: either could move or rewrite a context slot
// a callback reads or fills.
func callbackFrames(in asm.Instructions, pcs []int, index map[int]int, targets targetBindings, frames []FrameFloor) (map[int]CtxSource, map[int]int, error) {
	refs, calls, landings := map[int][]int{}, map[int]bool{}, map[int]bool{}
	functions := []int{}
	for i, ins := range in {
		if !edge(ins) {
			continue
		}
		t, err := target(in, pcs, index, i)
		if err != nil {
			return nil, nil, inputError(InputOriginalCFG, "original edge: %v", err)
		}
		if !ins.IsFunctionReference() {
			landings[t] = true
			continue
		}
		functions = append(functions, t)
		if ins.IsLoadOfFunctionPointer() {
			refs[t] = append(refs[t], i)
		} else {
			calls[t] = true
		}
	}
	keys := slices.SortedFunc(maps.Keys(targets), func(a, b targetKey) int { return cmp.Or(cmp.Compare(a.site, b.site), cmp.Compare(a.when, b.when)) })
	out, owner, bodies := map[int]CtxSource{}, map[int]int{}, map[int]map[int]bool{}
	entry := body(in, pcs, index, 0)
	for _, key := range keys {
		binding := targets[key]
		if binding.ctx == nil || binding.ctx.Param == 0 {
			continue
		}
		start := -1
		for _, f := range functions {
			if f <= key.site && f > start {
				start = f
			}
		}
		if start < 0 || len(refs[start]) == 0 {
			return nil, nil, reject(CtxProvenance, "site %d is not in a function used as a callback", key.site)
		}
		if bodies[start] == nil {
			bodies[start] = body(in, pcs, index, start)
		}
		if !bodies[start][key.site] {
			return nil, nil, reject(CtxProvenance, "site %d is not reachable from the callback at %d", key.site, start)
		}
		owner[key.site] = start
		if prior, ok := out[start]; ok {
			if !prior.equal(*binding.ctx) {
				return nil, nil, inputError(InputTarget, "inconsistent callback context premises in the function at %d", start)
			}
			continue
		}
		out[start] = *binding.ctx
		if calls[start] {
			return nil, nil, reject(CtxProvenance, "the callback at %d is also called directly", start)
		}
		for _, ref := range refs[start] {
			if !entry[ref] {
				return nil, nil, reject(CtxProvenance, "the callback at %d is referenced outside the entry function", start)
			}
			use, from, call, why := ctxflow.CallbackCall(in, ref)
			if why != "" {
				return nil, nil, reject(CtxProvenance, "the callback at %d: %s", start, why)
			}
			if int(use.Param) != binding.ctx.Param || use.Arg != binding.ctx.Arg {
				return nil, nil, reject(CtxProvenance, "the callback at %d gets r%d = fp%d, not the premise's r%d = fp%d", start, use.Param, use.Arg, binding.ctx.Param, binding.ctx.Arg)
			}
			for j := from + 1; j <= call; j++ {
				if landings[j] {
					return nil, nil, reject(CtxProvenance, "a branch lands at %d, between the callback context at %d and the helper call at %d", j, from, call)
				}
			}
		}
	}
	if len(out) != 0 {
		// A frame at an unreferenced root, such as an exception callback, is
		// outside both.
		for _, frame := range frames {
			inside := frame.Start != 0 && entry[frame.Start]
			for start, b := range bodies {
				inside = inside || frame.Start != start && b[frame.Start]
			}
			if inside {
				return nil, nil, reject(CtxProvenance, "a frame floor starts at %d, inside the entry or a callback", frame.Start)
			}
		}
		for key, binding := range targets {
			if entry[key.site] && binding.ctx != nil && binding.ctx.Param == 0 && len(binding.ctx.Pass) == 0 {
				return nil, nil, reject(CtxProvenance, "entry site %d names a context source, which would rewrite the slot callbacks read", key.site)
			}
		}
	}
	return out, owner, nil
}

// body returns the instructions reachable from start through jumps and
// fall-through, without following calls.
func body(in asm.Instructions, pcs []int, index map[int]int, start int) map[int]bool {
	seen := map[int]bool{}
	work := []int{start}
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		if i < 0 || i >= len(in) || seen[i] {
			continue
		}
		seen[i] = true
		ins := in[i]
		if ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit {
			if t, err := target(in, pcs, index, i); err == nil {
				work = append(work, t)
			}
		}
		if !terminal(ins) {
			work = append(work, i+1)
		}
	}
	return seen
}

func stackAudit(ins asm.Instruction, floor int) error {
	cl := ins.OpCode.Class()
	if cl == asm.LdXClass && ins.Src == asm.RFP || (cl == asm.StClass || cl == asm.StXClass) && ins.Dst == asm.RFP {
		if int(ins.Offset) < floor {
			return reject(StackAudit, "direct stack access %d below audit %d", ins.Offset, floor)
		}
	}
	return nil
}
func supportedHelper(ins asm.Instruction) bool {
	if !ins.IsBuiltinCall() {
		return false
	}
	switch asm.BuiltinFunc(ins.Constant) {
	case asm.FnMapLookupElem, asm.FnMapLookupPercpuElem, asm.FnMapUpdateElem, asm.FnMapDeleteElem, asm.FnMapPushElem, asm.FnMapPopElem, asm.FnMapPeekElem, asm.FnTailCall:
		return true
	}
	return false
}
func stackSpill(ins asm.Instruction) bool {
	return ins.OpCode == asm.StoreMem(asm.RFP, 0, asm.R0, asm.DWord).OpCode && ins.Dst == asm.RFP
}
func checkBefore(helper asm.Instruction, is asm.Instructions, f, lowest int, ctx *CtxSource) error {
	store := func(off int, r asm.Register) asm.Instruction { return asm.StoreMem(asm.RFP, int16(off), r, asm.DWord) }
	withCtx := func(v asm.Instructions) asm.Instructions {
		if ctx == nil {
			return v
		}
		switch {
		case ctx.Reg >= int(asm.R6) && ctx.Reg <= int(asm.R9) && ctx.Slot == 0:
			return append(v, store(f+slotContext, asm.Register(ctx.Reg)))
		case ctx.Reg == 0 && int(ctx.Slot) >= lowest && ctx.Slot <= -8 && ctx.Slot%8 == 0:
			return append(v, asm.LoadMem(asm.R0, asm.RFP, ctx.Slot, asm.DWord), store(f+slotContext, asm.R0))
		default:
			return nil
		}
	}
	var variants []asm.Instructions
	for _, withMap := range []bool{false, true} {
		v := asm.Instructions{store(f+slotKey, asm.R2)}
		switch asm.BuiltinFunc(helper.Constant) {
		case asm.FnTailCall:
			v = asm.Instructions{store(f+slotKey, asm.R3)}
			if withMap {
				v = append(v, store(f+slotMap, asm.R2))
			}
			variants = append(variants, slices.Clone(v))
			v = append(v, store(f+slotContext, asm.R1))
			variants = append(variants, v)
			continue
		case asm.FnMapUpdateElem:
			at := f + slotMap
			if withMap {
				at = f + slotValue
			}
			v = append(v, store(f+slotResult, asm.R4), store(at, asm.R3))
		case asm.FnMapPushElem:
			v = append(v, store(f+slotResult, asm.R3))
		}
		if withMap {
			v = append(v, store(f+slotMap, asm.R1))
		}
		if v = withCtx(v); v != nil {
			variants = append(variants, v)
		}
	}
	for _, v := range variants {
		if equal(is, v) {
			for _, ins := range is {
				if int(ins.Offset) < stackBottom {
					return reject(SpillBounds, "stack spill outside frame")
				}
			}
			return nil
		}
	}
	if ctx != nil {
		return reject(CtxProvenance, "callee context initialization does not match its premise")
	}
	return reject(PreludeShape, "not a helper observation spill sequence")
}
func equal(a, b asm.Instructions) bool { return slices.EqualFunc(a, b, same) }

func isU32Hook(is asm.Instructions) bool {
	return equal(is, asm.Instructions{asm.Mov.Reg32(asm.R0, asm.R1), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return()})
}
func checkHook(is asm.Instructions) error {
	if isU32Hook(is) || equal(is, asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}) {
		return nil
	}
	// A 4- or 8-byte read of ctx at 0, whatever the ctx type: of the supported
	// contexts the verifier allows the 8-byte read only for bpf_nf_ctx, and
	// neither read has a side effect.
	if len(is) < 3 || (!same(is[0], asm.LoadMem(asm.R0, asm.R1, 0, asm.Word)) && !same(is[0], asm.LoadMem(asm.R0, asm.R1, 0, asm.DWord))) || !equal(is[len(is)-2:], asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}) {
		return reject(HookShape, "not an observer hook")
	}
	body := is[1 : len(is)-2]
	// Typed nullable pointer pairs, or untrusted fault-handled loads.
	for _, regs := range [][]asm.Register{nil, {asm.R2}, {asm.R2, asm.R3}, {asm.R3}, {asm.R3, asm.R4}, {asm.R3, asm.R4, asm.R5}} {
		plain, guarded := asm.Instructions{}, asm.Instructions{}
		for _, r := range regs {
			load := asm.LoadMem(asm.R0, r, 0, asm.Byte)
			plain = append(plain, load)
			j := asm.JEq.Imm(r, 0, "")
			j.Offset = 1
			guarded = append(guarded, j, load)
		}
		if equal(body, plain) || equal(body, guarded) {
			return nil
		}
	}
	return reject(HookBody, "not an observer pointer-read sequence (stores/calls forbidden)")
}

// checkWrapperPrelude accepts only the load of a planned ctx source into R4.
// R4 is dead there: a lookup reads R1, R2 and, per-CPU, R3, and R1-R5 are
// unreadable after a helper.
func checkWrapperPrelude(ins asm.Instruction, ctx *CtxSource, lowest, f int, entryCtx bool) error {
	var want asm.Instruction
	switch {
	case ctx != nil && (ctx.Param != 0 || len(ctx.Pass) != 0):
		// Its Slot is zero: the context reaches the site through the
		// function's prologue, which a wrapped site never has.
		return reject(WrapperPrelude, "a callback or passed context has no wrapper prelude")
	case ctx != nil && ctx.Reg != 0:
		want = asm.Mov.Reg(asm.R4, asm.Register(ctx.Reg))
	case ctx != nil:
		if ctx.Slot >= 0 {
			return reject(WrapperPrelude, "wrapper context slot %d is not below r10", ctx.Slot)
		}
		if int(ctx.Slot) < lowest {
			return reject(CtxProvenance, "wrapper context slot %d is below the frame floor", ctx.Slot)
		}
		want = asm.LoadMem(asm.R4, asm.RFP, ctx.Slot, asm.DWord)
	case entryCtx && f+slotContext >= stackBottom:
		want = asm.LoadMem(asm.R4, asm.RFP, int16(f+slotContext), asm.DWord)
	default:
		return reject(WrapperPrelude, "site outside the entry frame has no planned context source")
	}
	if !same(ins, want) {
		return reject(WrapperPrelude, "not the planned context load into R4")
	}
	return nil
}

// checkWrapper accepts exactly the function pkg/inject generates in place of
// this site's lookup helper, built from the site's plan. A wrapped site is the
// original helper call in a callee:
//   - The helper is the original's, with the original's R1, R2 and R3: nothing
//     writes them between the site and the helper.
//   - R0 returns to the caller unchanged on every path: it goes to R8 at once
//     and comes back after the hook. What the caller reads afterwards is what
//     it read after the helper, since R1-R5 are unreadable either way.
//   - The caller's R6-R10 and stack stay intact: the wrapper names no R10, and
//     the BPF calling convention gives a callee its own R6-R9.
//   - Each result arm the plan names calls its hook with the planned arguments
//     and no others: R6 is R4 on entry, the ctx of checkWrapperPrelude; R7 the
//     key; R0 the value; R9 the map, kept only when a hook takes it; the site
//     is the planned immediate. An arm the plan does not name calls nothing.
//
// The guard may test for a hit or a miss first; anything else fails closed.
func checkWrapper(site int, helper asm.Instruction, out asm.Instructions, pcs []int, idx map[int]int, w Span, hooks map[int]bool, targets targetBindings) error {
	if c := asm.BuiltinFunc(helper.Constant); !helper.IsBuiltinCall() || c != asm.FnMapLookupElem && c != asm.FnMapLookupPercpuElem {
		return reject(WrapperShape, "only a lookup helper can move into a wrapper")
	}
	hit, miss := targets.arm(site, TargetHit), targets.arm(site, TargetMiss)
	if hit == nil && miss == nil {
		return reject(CallTarget, "wrapped site %d has no planned hook", site)
	}
	withMap := false
	for _, b := range []*targetBinding{hit, miss} {
		if b != nil && b.args == nil {
			return inputError(InputTarget, "wrapped site %d target has no planned arguments", site)
		}
		withMap = withMap || b != nil && slices.Contains(b.args, ArgMap)
	}
	from := map[ArgRole]asm.Register{ArgCtx: asm.R6, ArgKey: asm.R7, ArgValue: asm.R0, ArgMap: asm.R9}
	// An arm's argument moves and its call, whose target hookCall checks.
	arm := func(b *targetBinding) asm.Instructions {
		var is asm.Instructions
		for i, role := range b.args {
			if role == ArgSite {
				is = append(is, asm.Mov.Imm32(asm.R1+asm.Register(i), b.sitePC))
			} else {
				is = append(is, asm.Mov.Reg(asm.R1+asm.Register(i), from[role]))
			}
		}
		return append(is, asm.Call.Label(""))
	}
	guard := func(j asm.JumpOp, offset int) asm.Instruction {
		ins := asm.JEq.Imm(asm.R0, 0, "")
		if j == asm.JNE {
			ins = asm.JNE.Imm(asm.R0, 0, "")
		}
		ins.Offset = int16(offset)
		return ins
	}
	var bodies []asm.Instructions
	switch {
	case hit != nil && miss != nil:
		onHit, onMiss := arm(hit), arm(miss)
		bodies = append(bodies,
			slices.Concat(asm.Instructions{guard(asm.JEq, len(onHit)+1)}, onHit, asm.Instructions{jaBy(len(onMiss))}, onMiss),
			slices.Concat(asm.Instructions{guard(asm.JNE, len(onMiss)+1)}, onMiss, asm.Instructions{jaBy(len(onHit))}, onHit))
	case hit != nil:
		onHit := arm(hit)
		bodies = append(bodies,
			slices.Concat(asm.Instructions{guard(asm.JEq, len(onHit))}, onHit),
			slices.Concat(asm.Instructions{guard(asm.JNE, 1), jaBy(len(onHit))}, onHit))
	default:
		onMiss := arm(miss)
		bodies = append(bodies, slices.Concat(asm.Instructions{guard(asm.JNE, len(onMiss))}, onMiss))
	}
	head := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R4), asm.Mov.Reg(asm.R7, asm.R2)}
	if withMap {
		head = append(head, asm.Mov.Reg(asm.R9, asm.R1))
	}
	head = append(head, helper, asm.Mov.Reg(asm.R8, asm.R0))
	tail := asm.Instructions{asm.Mov.Reg(asm.R0, asm.R8), asm.Return()}
	is := out[w.Start:w.End]
	call := asm.Call.Label("")
	for _, body := range bodies {
		want := slices.Concat(head, body, tail)
		if len(want) != len(is) || !slices.EqualFunc(is, want, func(a, b asm.Instruction) bool {
			if b.OpCode == call.OpCode && b.Src == call.Src {
				return a.IsFunctionCall() && a.OpCode == call.OpCode
			}
			return same(a, b)
		}) {
			continue
		}
		// The arm that runs on a hit is the one after a JEq guard.
		first, second := TargetHit, TargetMiss
		if body[0].OpCode.JumpOp() == asm.JNE {
			first, second = TargetMiss, TargetHit
		}
		if hit == nil || miss == nil {
			first, second = TargetMiss, TargetMiss
			if miss == nil {
				first, second = TargetHit, TargetHit
			}
		}
		n := 0
		for j := range body {
			if !body[j].IsFunctionCall() {
				continue
			}
			when := first
			if n > 0 {
				when = second
			}
			n++
			if _, err := hookCall(out, pcs, idx, w.Start+len(head)+j, hooks, targets, site, when, true); err != nil {
				return err
			}
		}
		return nil
	}
	return reject(WrapperShape, "not the planned lookup wrapper body")
}

func jaBy(n int) asm.Instruction {
	ja := asm.Ja.Label("")
	ja.Offset = int16(n)
	return ja
}

type targetKey struct {
	site int
	when TargetWhen
}

type targetBinding struct {
	hook   int
	used   bool
	ctx    *CtxSource
	args   []ArgRole
	sitePC int32
}

type targetBindings map[targetKey]*targetBinding

func newTargetBindings(targets []SiteTarget, sites int, hooks map[int]bool) (targetBindings, error) {
	b := make(targetBindings, len(targets))
	ctxBySite := map[int]CtxSource{}
	ctxSet := map[int]bool{}
	for _, target := range targets {
		if target.Site < -1 || target.Site >= sites || !hooks[target.Hook] {
			return nil, inputError(InputTarget, "invalid site target %+v", target)
		}
		if target.Ctx != nil {
			ctx := target.Ctx
			plain := ctx.Param == 0 && ctx.Arg == 0 && len(ctx.Pass) == 0
			validReg := plain && ctx.Reg >= int(asm.R6) && ctx.Reg <= int(asm.R9) && ctx.Slot == 0
			validSlot := plain && ctx.Reg == 0 && ctx.Slot <= -8 && ctx.Slot >= stackBottom && ctx.Slot%8 == 0
			validCallback := ctx.Reg == 0 && ctx.Slot == 0 && len(ctx.Pass) == 0 && (ctx.Param == int(asm.R2) || ctx.Param == int(asm.R4)) && ctx.Arg <= -8 && ctx.Arg >= stackBottom
			validPass := ctx.Reg == 0 && ctx.Slot == 0 && ctx.Param == 0 && ctx.Arg == 0 && len(ctx.Pass) != 0
			for _, frame := range ctx.Pass {
				validPass = validPass && frame.Start > 0 && frame.Start < sites && frame.Reg >= int(asm.R1) && frame.Reg <= int(asm.R5)
			}
			if target.Site < 0 || !validReg && !validSlot && !validCallback && !validPass {
				return nil, inputError(InputTarget, "invalid context source in site target %+v", target)
			}
		}
		ctx := CtxSource{}
		if target.Ctx != nil {
			ctx = *target.Ctx
		}
		if prior, ok := ctxBySite[target.Site]; ok && (!prior.equal(ctx) || ctxSet[target.Site] != (target.Ctx != nil)) {
			return nil, inputError(InputTarget, "inconsistent context sources at site %d", target.Site)
		}
		ctxBySite[target.Site] = ctx
		ctxSet[target.Site] = target.Ctx != nil
		switch target.When {
		case TargetHit, TargetMiss, TargetAny, TargetError:
		default:
			return nil, inputError(InputTarget, "invalid site target condition %q", target.When)
		}
		if target.Args != nil && (target.Site < 0 || !slices.ContainsFunc(lookupABIs, func(abi []ArgRole) bool { return slices.Equal(abi, target.Args) })) {
			return nil, inputError(InputTarget, "invalid hook arguments in site target %+v", target)
		}
		if target.SitePC != 0 && !slices.Contains(target.Args, ArgSite) || target.SitePC < 0 {
			return nil, inputError(InputTarget, "site PC without a site argument in site target %+v", target)
		}
		key := targetKey{target.Site, target.When}
		if _, ok := b[key]; ok {
			return nil, inputError(InputTarget, "duplicate site target site=%d when=%s", target.Site, target.When)
		}
		b[key] = &targetBinding{hook: target.Hook, ctx: target.Ctx, args: target.Args, sitePC: target.SitePC}
	}
	return b, nil
}

func (b targetBindings) ctxForSite(site int) *CtxSource {
	var found *CtxSource
	for key, target := range b {
		if key.site != site || target.ctx == nil {
			continue
		}
		if found == nil {
			copy := *target.ctx
			found = &copy
		}
	}
	return found
}

// arm is the target of a lookup result arm: its own, or the site's any.
func (b targetBindings) arm(site int, when TargetWhen) *targetBinding {
	if target := b[targetKey{site, when}]; target != nil {
		return target
	}
	return b[targetKey{site, TargetAny}]
}

func (b targetBindings) consume(site int, when TargetWhen, hook int, lookupArm bool) (*targetBinding, error) {
	target := b[targetKey{site, when}]
	if target == nil && lookupArm {
		target = b.arm(site, when)
	}
	if target == nil {
		for planned := range b {
			if planned.site == site {
				return nil, reject(CallTarget, "site %d has no target for %s", site, when)
			}
		}
		if len(b) != 0 {
			return nil, reject(CallTarget, "call at unplanned site %d", site)
		}
		return nil, inputError(InputTargetMissing, "site %d has no target binding", site)
	}
	if hook != target.hook {
		return nil, reject(CallTarget, "site %d %s call targets hook %d; expected %d", site, when, hook, target.hook)
	}
	target.used = true
	return target, nil
}

// planned reports whether the plan expects a hook on this result arm.
func (b targetBindings) planned(site int, when TargetWhen, lookup bool) bool {
	if b[targetKey{site, when}] != nil {
		return true
	}
	return lookup && (when == TargetHit || when == TargetMiss) && b[targetKey{site, TargetAny}] != nil
}

func (b targetBindings) checkUsed() error {
	for key, target := range b {
		if !target.used {
			return reject(CallTarget, "planned site target is not called: site=%d when=%s hook=%d", key.site, key.when, target.hook)
		}
	}
	return nil
}

func hookCall(out asm.Instructions, pcs []int, idx map[int]int, j int, hooks map[int]bool, targets targetBindings, site int, when TargetWhen, lookupArm bool) (*targetBinding, error) {
	ins := out[j]
	if !ins.IsFunctionCall() {
		return nil, reject(CallKind, "inserted call is not bpf-to-bpf")
	}
	t, e := target(out, pcs, idx, j)
	if e != nil {
		return nil, e
	}
	if !hooks[t] {
		return nil, reject(CallTarget, "inserted call targets non-hook %d", t)
	}
	return targets.consume(site, when, t, lookupArm)
}
func checkEntry(is, out asm.Instructions, pcs []int, idx map[int]int, js []int, hooks map[int]bool, targets targetBindings, f int) error {
	if !same(is[0], asm.StoreMem(asm.RFP, int16(f+slotContext), asm.R1, asm.DWord)) || f+slotContext < stackBottom {
		return reject(EntrySpill, "not entry context spill")
	}
	if len(is) == 1 {
		return nil
	}
	call := 1
	if len(is) == 7 {
		if !equal(is[1:5], asm.Instructions{asm.Mov.Imm32(asm.R2, -1), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 0)}) {
			return reject(EntryArguments, "invalid dispatch entry arguments")
		}
		call = 5
	}
	if len(is) != call+2 || !same(is[len(is)-1], asm.LoadMem(asm.R1, asm.RFP, int16(f+slotContext), asm.DWord)) {
		return reject(EntryRestore, "not entry call/restore")
	}
	_, err := hookCall(out, pcs, idx, js[call], hooks, targets, -1, TargetAny, false)
	return err
}

func terminal(ins asm.Instruction) bool {
	return ins.OpCode.Class().IsJump() && (ins.OpCode.JumpOp() == asm.Exit || ins.OpCode.JumpOp() == asm.Ja)
}

func differingFields(a, b asm.Instruction) string {
	var fields []string
	if a.OpCode != b.OpCode {
		fields = append(fields, fmt.Sprintf("opcode %s -> %s", a.OpCode, b.OpCode))
	}
	if a.Dst != b.Dst {
		fields = append(fields, fmt.Sprintf("dst %s -> %s", a.Dst, b.Dst))
	}
	if a.Src != b.Src {
		fields = append(fields, fmt.Sprintf("src %s -> %s", a.Src, b.Src))
	}
	if a.Offset != b.Offset {
		fields = append(fields, fmt.Sprintf("offset %d -> %d", a.Offset, b.Offset))
	}
	if a.Constant != b.Constant {
		fields = append(fields, fmt.Sprintf("constant %d -> %d", a.Constant, b.Constant))
	}
	return strings.Join(fields, ", ")
}
