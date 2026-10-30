// Package injectcheck independently checks the instruction-level safety of an
// injection. It does not import the transformer. A certificate supplies only
// correspondence hints: every hint and every otherwise unaccounted bytecode
// instruction is checked. Acceptance is conditional on the original and
// transformed programs being valid BPF, the BPF calling convention,
// and the caller's trusted stack-alias audit.
package injectcheck

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
)

// Span is a half-open range of decoded instruction indices, not raw slots.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Certificate is untrusted layout metadata. Original[i] locates original
// instruction i in the output; Hooks lists all inserted function bodies.
type Certificate struct {
	Original []int  `json:"original"`
	Hooks    []Span `json:"hooks"`
}

// Counts reports input size, checked sites and declared hook bodies.
// Sites is partial when Check returns an error.
type Counts struct {
	Instructions int `json:"instructions"`
	Sites        int `json:"sites"`
	Hooks        int `json:"hooks"`
}

// Premises is the trusted caller audit, separate from the untrusted certificate.
type Premises struct {
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
	if len(c.Original) == 0 {
		return counts, inputError(InputCertificateEmpty, "certificate.original must not be empty")
	}
	if len(c.Original) != len(in) {
		return counts, inputError(InputCertificateLength, "certificate.original length %d differs from original length %d", len(c.Original), len(in))
	}
	if premises.LowestOffset > 0 || premises.LowestOffset < stackBottom {
		return counts, inputError(InputStackFloor, "lowest_offset must be in [-512,0], got %d", premises.LowestOffset)
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
	floor := int(premises.LowestOffset) &^ 7
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
	for j, owner := range owners {
		if owner < 0 {
			if err := noLoadMetadata(out[j]); err != nil {
				return counts, fmt.Errorf("transformed instruction %d: %w", j, err)
			}
		}
	}
	// Hook bodies were excluded above; reject any fall-through into one.
	for _, h := range c.Hooks {
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
	// A helper's prelude is the trailing sequence of stack spills before it.
	starts := slices.Clone(c.Original)
	before := make([]asm.Instructions, len(in))
	for i := range in {
		if !supportedHelper(in[i]) {
			continue
		}
		g := gaps[i]
		n := len(g)
		for n > 0 && stackSpill(out[g[n-1]]) {
			n--
		}
		if n < len(g) {
			starts[i] = g[n]
			for _, j := range g[n:] {
				before[i] = append(before[i], out[j])
			}
			gaps[i] = g[:n]
			if err := checkBefore(in[i], before[i], floor); err != nil {
				return counts, fmt.Errorf("site %d prelude: %w", i, err)
			}
		}
	}
	// The one-time entry prologue is excluded from backward edges to original 0.
	starts[0] = c.Original[0]
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
			if u != starts[t] {
				return fail(EdgeTarget, "edge %d targets %d; expected %d (original %d)", i, u, starts[t], t)
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
		if err := stackAudit(a, int(premises.LowestOffset)); err != nil {
			return counts, fmt.Errorf("original %d: %w", i, err)
		}
	}
	gather := func(js []int) asm.Instructions {
		is := make(asm.Instructions, len(js))
		for i, j := range js {
			is[i] = out[j]
		}
		return is
	}
	if len(gaps[0]) > 0 {
		if err := checkEntry(gather(gaps[0]), out, npcs, ni, gaps[0], hooks, floor); err != nil {
			return counts, fmt.Errorf("entry: %w", err)
		}
	}
	for i := range in {
		after := gather(gaps[i+1])
		if len(before[i]) > 0 {
			if err := checkAfter(in[i], before[i], after, out, npcs, ni, gaps[i+1], hooks, floor, len(gaps[0]) > 0 && i < entryEnd); err != nil {
				return counts, fmt.Errorf("site %d: %w", i, err)
			}
			counts.Sites++
		} else if len(after) > 0 {
			if err := checkU32(in[i], after, out, npcs, ni, gaps[i+1], hooks, floor, live[i+1]); err != nil {
				return counts, fmt.Errorf("gap after %d: %w", i, err)
			}
			counts.Sites++
		}
	}
	return counts, nil
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
func checkBefore(helper asm.Instruction, is asm.Instructions, f int) error {
	store := func(off int, r asm.Register) asm.Instruction { return asm.StoreMem(asm.RFP, int16(off), r, asm.DWord) }
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
		variants = append(variants, v)
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
	if len(is) < 3 || !same(is[0], asm.LoadMem(asm.R0, asm.R1, 0, asm.Word)) || !equal(is[len(is)-2:], asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}) {
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

func hookCall(out asm.Instructions, pcs []int, idx map[int]int, j int, hooks map[int]bool) error {
	ins := out[j]
	if !ins.IsFunctionCall() {
		return reject(CallKind, "inserted call is not bpf-to-bpf")
	}
	t, e := target(out, pcs, idx, j)
	if e != nil {
		return e
	}
	if !hooks[t] {
		return reject(CallTarget, "inserted call targets non-hook %d", t)
	}
	return nil
}
func checkEntry(is, out asm.Instructions, pcs []int, idx map[int]int, js []int, hooks map[int]bool, f int) error {
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
	return hookCall(out, pcs, idx, js[call], hooks)
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
