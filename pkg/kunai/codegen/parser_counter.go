package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// ParserCounter slot allocator. Each ParserCounter() instance the
// vocab declares gets one stack slot, addressable from both the main
// program (R10-relative) and any bpf_loop callback (R2-relative via
// mainStackOffsetFromCb). Counters are machine-local — they live only
// during the parser machine's execution and the slots are reused
// across machines, so a small fixed region suffices.
//
// The slot region carves into the 16-byte gap [-224, -208) that sits
// as a documentation margin between bpf_loop ctx [-208, -176) and
// the where-layer slots starting at -224. Two slots cover every
// vocab in the tree (TCP and IPv4 declare one counter each); raise
// parserCounterMaxSlots and ensure the gap (or its replacement) is
// wide enough before adding a third.
const (
	parserCounterSlotsBase int16 = -216
	parserCounterSlotSize  int16 = 8
	parserCounterMaxSlots        = 2
)

// parserCounterSlot returns the R10-relative stack offset for the
// counter at index `idx` (0-based) within the parser machine's
// declaration list.
func parserCounterSlot(idx int) (int16, error) {
	if idx < 0 || idx >= parserCounterMaxSlots {
		return 0, fmt.Errorf("%w: parser counter slot %d out of range [0, %d)", ErrNotImplemented, idx, parserCounterMaxSlots)
	}
	return parserCounterSlotsBase - int16(idx)*parserCounterSlotSize, nil
}

// counterSlot looks up the slot by counter name. The vocab loader
// already scope-checks counter ops against the declared instances,
// so an unknown name here is a codegen-only invariant violation.
func (c *pmCtx) counterSlot(name string) (int16, error) {
	for i, ci := range c.machine.Counters {
		if ci.Name == name {
			return parserCounterSlot(i)
		}
	}
	return 0, fmt.Errorf("%w: counter %q referenced by codegen but not declared in machine", ErrNotImplemented, name)
}

// emitCounterSlotInit zero-inits every counter slot at machine entry.
// is_zero() reads the slot, and BPF rejects loads from un-stored
// stack regions; the zero default also makes any path that reaches
// is_zero before a set take the "true" branch (= exit the loop),
// which is the safe fall-through for trailer-bounded walks.
func (c *pmCtx) emitCounterSlotInit() (asm.Instructions, error) {
	return emitFillStackSlots(0, len(c.machine.Counters), parserCounterSlot)
}

// counterEnv parameterises the register conventions for counter ops.
// Inline emit (main program) and the bpf_loop callback see different
// pieces in different registers; centralising the differences here
// keeps the per-op emit branches uniform. Field naming mirrors
// trailEnv so reading both side-by-side stays straightforward.
type counterEnv struct {
	// stackBase carries the slot pointer. Inline: R10. Callback: R2
	// (= ctx pointer; resolveSlot wraps via mainStackOffsetFromCb).
	stackBase    asm.Register
	scratchStart asm.Register
	offset       asm.Register
	scratchEnd   asm.Register
	// scratchA holds the loaded slot value during decrement / is_zero
	// and the computed byte count during set.
	scratchA asm.Register
	// scratchB is the addr scratch for byte-load arithmetic in set;
	// unused by decrement / is_zero.
	scratchB    asm.Register
	resolveSlot func(int16) int16
}

func inlineCounterEnv() counterEnv {
	return counterEnv{
		stackBase:    asm.R10,
		scratchStart: asm.R0,
		offset:       offsetBase,
		scratchEnd:   asm.R1,
		scratchA:     asm.R5,
		scratchB:     asm.R3,
		resolveSlot:  func(s int16) int16 { return s },
	}
}

func callbackCounterEnv() counterEnv {
	return counterEnv{
		stackBase:    asm.R2,
		scratchStart: asm.R4,
		offset:       asm.R3,
		scratchEnd:   asm.R5,
		scratchA:     asm.R1,
		scratchB:     asm.R0,
		resolveSlot:  mainStackOffsetFromCb,
	}
}

// emitCounterOp lowers one CounterOp under a given register/ABI env.
// fixedHs is the byte distance from the just-extracted header start
// to the current R4 (= layer's primary header size for set; ignored
// otherwise). failLabel is the destination on bounds-check failure
// (dslReject inline, breakLabel inside a callback).
func (c *pmCtx) emitCounterOp(op vocab.CounterOp, fixedHs int, env counterEnv, failLabel string) (asm.Instructions, error) {
	slot, err := c.counterSlot(op.Counter)
	if err != nil {
		return nil, err
	}
	resolvedSlot := env.resolveSlot(slot)
	switch op.Kind {
	case vocab.CounterOpSet:
		body, err := emitCounterSetValue(fixedHs, op.Skip, env, failLabel)
		if err != nil {
			return nil, err
		}
		body = append(body, asm.StoreMem(env.stackBase, resolvedSlot, env.scratchA, asm.DWord))
		return body, nil
	case vocab.CounterOpDecrement:
		switch {
		case op.DecrementLookaheadByteOffR:
			// Lookahead form: byte sits at R3 + DecrementLookaheadByteOff
			// (no extract precedes, so no fixedHs adjustment).
			loadByteOff := int32(op.DecrementLookaheadByteOff)
			var insns asm.Instructions
			insns = append(insns, foldOffsetIntoScalar(env.scratchB, env.offset, loadByteOff, failLabel)...)
			insns = append(insns, boundedScalarLoad(env.scratchA, env.scratchStart, env.scratchB, env.scratchEnd, asm.Byte, failLabel)...)
			insns = append(insns,
				asm.LoadMem(env.scratchB, env.stackBase, resolvedSlot, asm.DWord),
				asm.Sub.Reg(env.scratchB, env.scratchA),
				asm.StoreMem(env.stackBase, resolvedSlot, env.scratchB, asm.DWord),
			)
			return insns, nil
		case op.DecrementFieldName != "":
			// Field-expr form: load the aux byte at R3 + (-fixedHs +
			// DecrementByteOff) into scratchA, then Sub.Reg into the
			// counter slot loaded into scratchB. scratchB is clobbered
			// by the address fold then reused for the slot.
			loadByteOff := int32(-fixedHs + op.DecrementByteOff)
			var insns asm.Instructions
			insns = append(insns, foldOffsetIntoScalar(env.scratchB, env.offset, loadByteOff, failLabel)...)
			insns = append(insns, boundedScalarLoad(env.scratchA, env.scratchStart, env.scratchB, env.scratchEnd, asm.Byte, failLabel)...)
			insns = append(insns,
				asm.LoadMem(env.scratchB, env.stackBase, resolvedSlot, asm.DWord),
				asm.Sub.Reg(env.scratchB, env.scratchA),
				asm.StoreMem(env.stackBase, resolvedSlot, env.scratchB, asm.DWord),
			)
			return insns, nil
		}
		return asm.Instructions{
			asm.LoadMem(env.scratchA, env.stackBase, resolvedSlot, asm.DWord),
			asm.Sub.Imm(env.scratchA, int32(op.LiteralBytes)),
			asm.StoreMem(env.stackBase, resolvedSlot, env.scratchA, asm.DWord),
		}, nil
	}
	return nil, fmt.Errorf("%w: unknown CounterOp kind %d", ErrNotImplemented, op.Kind)
}

// emitCounterSetValue computes `((header_byte & LenMask) >> LenShift)
// * Scale - Base + Addend` and leaves the result in env.scratchA.
// Mirrors the scalar-compute prefix of emitVariableTrail; stops before
// the R4 advance because counter set stores the count instead of
// consuming it. The bare-cast add form (Scale=1, Base=0, Addend>0)
// yields an element count (SRH segments = last_entry + 1); the shifted
// forms yield a byte count (Base subtract, Addend=0).
func emitCounterSetValue(fixedHs int, vt *vocab.HeaderLength, env counterEnv, failLabel string) (asm.Instructions, error) {
	if vt == nil {
		return nil, fmt.Errorf("%w: counter set with nil HeaderLength", ErrNotImplemented)
	}
	shift := log2PowerOfTwo(vt.Scale)
	if shift < 0 {
		return nil, fmt.Errorf("%w: counter set scale %d is not a power of two", ErrNotImplemented, vt.Scale)
	}
	loadByteOff := int32(-fixedHs + vt.LenByteOff)
	var insns asm.Instructions
	insns = append(insns, foldOffsetIntoScalar(env.scratchB, env.offset, loadByteOff, failLabel)...)
	insns = append(insns, boundedScalarLoad(env.scratchA, env.scratchStart, env.scratchB, env.scratchEnd, asm.Byte, failLabel)...)
	if vt.LenMask != 0 {
		insns = append(insns, asm.And.Imm(env.scratchA, int32(vt.LenMask)))
	}
	if vt.LenShift > 0 {
		insns = append(insns, asm.RSh.Imm(env.scratchA, int32(vt.LenShift)))
	}
	if shift > 0 {
		insns = append(insns, asm.LSh.Imm(env.scratchA, int32(shift)))
	}
	if vt.Base > 0 {
		insns = append(insns,
			asm.JLT.Imm(env.scratchA, int32(vt.Base), failLabel),
			asm.Sub.Imm(env.scratchA, int32(vt.Base)),
		)
	}
	if vt.Addend > 0 {
		// Bare-cast element-count add form (e.g. SRH last_entry + 1).
		// scratchA holds the field byte (scale=1, no Base), so a plain
		// Add yields the element count with no underflow risk.
		insns = append(insns, asm.Add.Imm(env.scratchA, int32(vt.Addend)))
	}
	return insns, nil
}

// emitCounterIsZeroProbe emits the 2-insn `LoadMem; JEq.Imm 0,
// trueLabel` probe shared by every counter-dispatch site. Returning
// the probe alone (without a trailing Ja) lets the multi-state path
// fall through into an inlined sibling body, while regular select
// emit appends `Ja falseLabel` via emitCounterIsZeroBranches.
func (c *pmCtx) emitCounterIsZeroProbe(counter, trueLabel string, env counterEnv) (asm.Instructions, error) {
	slot, err := c.counterSlot(counter)
	if err != nil {
		return nil, err
	}
	return asm.Instructions{
		asm.LoadMem(env.scratchA, env.stackBase, env.resolveSlot(slot), asm.DWord),
		asm.JEq.Imm(env.scratchA, 0, trueLabel),
	}, nil
}

// emitCounterIsZeroBranches probes the counter slot and Ja's to
// either trueLabel (== 0) or falseLabel (!= 0). Used inside the
// inline transition emit path and the callback transition emit path
// where both arms route to a known label.
func (c *pmCtx) emitCounterIsZeroBranches(counter, trueLabel, falseLabel string, env counterEnv) (asm.Instructions, error) {
	insns, err := c.emitCounterIsZeroProbe(counter, trueLabel, env)
	if err != nil {
		return nil, err
	}
	return append(insns, asm.Ja.Label(falseLabel)), nil
}

// counterIsZeroLabels resolves a SelectOp keyed on
// `<counter>.is_zero()` into the (trueLabel, falseLabel) pair the
// branch emit consumes. The MVP only models the two boolean-literal
// cases — true/false — and rejects malformed shapes (wildcards,
// duplicate values, missing arms).
func counterIsZeroLabels(sel *vocab.SelectOp, branch func(int) string) (trueLabel, falseLabel string, err error) {
	for _, kase := range sel.Cases {
		if len(kase.Values) != 1 {
			return "", "", fmt.Errorf("%w: counter is_zero select has %d values per case (want 1)", ErrNotImplemented, len(kase.Values))
		}
		mv := kase.Values[0]
		switch {
		case mv.IsWildcard:
			if trueLabel != "" || falseLabel != "" {
				return "", "", fmt.Errorf("%w: counter is_zero select mixes wildcard with explicit cases", ErrNotImplemented)
			}
			trueLabel = branch(kase.Target)
			falseLabel = branch(kase.Target)
		case mv.IsBool && mv.Bool:
			if trueLabel != "" {
				return "", "", fmt.Errorf("%w: counter is_zero select declares true branch twice", ErrNotImplemented)
			}
			trueLabel = branch(kase.Target)
		case mv.IsBool && !mv.Bool:
			if falseLabel != "" {
				return "", "", fmt.Errorf("%w: counter is_zero select declares false branch twice", ErrNotImplemented)
			}
			falseLabel = branch(kase.Target)
		default:
			return "", "", fmt.Errorf("%w: counter is_zero case must use true/false (got int %d)", ErrNotImplemented, mv.Value)
		}
	}
	defaultLabel := branch(sel.Default)
	if trueLabel == "" {
		trueLabel = defaultLabel
	}
	if falseLabel == "" {
		falseLabel = defaultLabel
	}
	return trueLabel, falseLabel, nil
}
