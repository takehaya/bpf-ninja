package codegen

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// whereCtx carries the shared state that codegen for a where
// expression needs: the program (for absolute layer offsets), the
// host capabilities (whether action atoms are available and how to
// fetch their value), a monotonically increasing label counter so
// or/not branches get unique landings, and a memoized layer-anchor
// cache.
type whereCtx struct {
	p       *ir.Program
	lang    LangCaps
	labels  int
	anchors map[*ir.LayerInstance]layerAnchor
	queried queriedOptions
	// wideHold is how many arith slots above arith128ReservedSlots hold
	// the left results of enclosing 128-bit `x ± y` nodes whose both
	// sides park (genArith128FieldOpField); a sub-64-bit expression
	// inside them starts above these.
	wideHold int
	// boolEqDepth is the current `Bool == Bool` nesting level. genBoolEq
	// uses it to pick a distinct LHS-save slot per level so a nested
	// bool-eq operand does not clobber an enclosing one.
	boolEqDepth int
	// atomFail is the fail label of the where atom being generated. Field
	// loads that find an option, gated aux, or stack entry absent jump
	// here so the atom evaluates false (spec D-027, D-031) instead of
	// rejecting the packet; empty outside an atom (then dslReject).
	atomFail string
	// presentLayers holds absentable layers an enclosing any()/all() has
	// already guarded as present, so the atoms it unrolls skip their own
	// guard.
	presentLayers map[*ir.LayerInstance]bool
	// absentable caches hasAbsentableLayer.
	absentable *bool
	// callbacks accumulates bpf_loop callback subprograms emitted while
	// generating the where clause (currently the aux-walk any()/all()
	// loop). They are returned out of genCondition and appended to
	// Output.Callbacks after the main program's return, alongside the
	// per-layer chain callbacks.
	callbacks asm.Instructions
}

func (c *whereCtx) freshLabel(prefix string) string {
	c.labels++
	return fmt.Sprintf("dsl_%s_%d", prefix, c.labels)
}

// layerAnchorFor returns the addressing strategy for a layer's start
// in the scratch buffer, memoised after the first lookup. Layers
// flagged NeedsRuntimeOffset (resolver mark for "at a runtime offset")
// route through their per-layer entry slot; the rest stay on the
// static R0+prefix path. Errors propagate from the static path
// (e.g. quantified layer in prefix) and from the stack plan (a marked
// layer without a slot is a planning bug).
func (c *whereCtx) layerAnchorFor(l *ir.LayerInstance) (layerAnchor, error) {
	if a, ok := c.anchors[l]; ok {
		return a, nil
	}
	var (
		anchor layerAnchor
		err    error
	)
	if l != nil && l.NeedsRuntimeOffset {
		var slot int16
		slot, err = c.queried.entrySlot(l)
		if err == nil {
			anchor = slotAnchor(slot)
		}
	} else {
		var off int
		off, err = layerAbsoluteOffset(l, c.p)
		if err == nil {
			anchor = absAnchor(off)
		}
	}
	if err != nil {
		return layerAnchor{}, err
	}
	c.anchors[l] = anchor
	return anchor, nil
}

// genCondition emits instructions that fall through when w evaluates
// to true and jump to failLabel when it evaluates to false. Errors
// surface with the condition's source position prefixed so users see
// which `where` atom blew up.
func genCondition(w *ir.Condition, lang LangCaps, p *ir.Program, qo queriedOptions, failLabel string) (asm.Instructions, asm.Instructions, error) {
	ctx := &whereCtx{p: p, lang: lang, anchors: make(map[*ir.LayerInstance]layerAnchor), queried: qo}
	insns, err := ctx.gen(w, failLabel)
	return insns, ctx.callbacks, withPos(err, w.Pos)
}

func (c *whereCtx) gen(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	w = foldBooleanConstants(w)
	if w == nil {
		return nil, nil
	}
	if w.Unsupported != "" {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, w.Unsupported)
	}
	switch w.Kind {
	case ast.WAtomAction:
		return genActionAtom(w, c.lang, failLabel)
	case ast.WAtomArith:
		return c.withLayerGuards(w, failLabel, func(w *ir.Condition, fail string) (asm.Instructions, error) {
			return c.withStackGuards(w, fail, c.genArithCompare)
		})
	case ast.WAtomLiteralCmp:
		return c.withLayerGuards(w, failLabel, func(w *ir.Condition, fail string) (asm.Instructions, error) {
			return c.withStackGuards(w, fail, c.genLiteralCompare)
		})
	case ast.WAnd:
		return c.genAnd(w, failLabel)
	case ast.WOr:
		return c.genOr(w, failLabel)
	case ast.WNot:
		return c.genNot(w, failLabel)
	case ast.WAny:
		return c.genAny(w, failLabel)
	case ast.WAll:
		return c.genAll(w, failLabel)
	case ast.WAtomBoolLit:
		return c.genBoolLit(w, failLabel)
	case ast.WAtomBoolExists:
		return c.withLayerGuards(w, failLabel, c.genBoolExists)
	case ast.WAtomBoolValid:
		return c.withLayerGuards(w, failLabel, c.genBoolValid)
	case ast.WAtomBoolEq:
		return c.genBoolEq(w, failLabel)
	}
	return nil, fmt.Errorf("%w: where kind %s", ErrNotImplemented, w.Kind)
}

// genBoolLit handles `where true` / `where false` after constant
// folding. `true` falls through (always match), `false` jumps to
// failLabel unconditionally (always reject).
func (c *whereCtx) genBoolLit(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w == nil {
		return nil, nil
	}
	if w.BoolLitValue {
		return nil, nil
	}
	return asm.Instructions{asm.Ja.Label(failLabel)}, nil
}

// genBoolExists handles `where <aux>.exists`. Reuses the existing
// aux-gating emit path: the FieldRef carries Aux information; codegen
// emits the gating predicate and falls through on extracted, jumps to
// failLabel on missing.
func (c *whereCtx) genBoolExists(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w == nil || w.BoolField == nil || w.BoolField.Aux == nil {
		return nil, fmt.Errorf("codegen: bool exists atom lacks aux reference")
	}
	// A TLV option exists iff the walk recorded its offset (slot ≠ sentinel).
	if slot, ok := c.dynamicOffsetSlotFor(w.BoolField); ok {
		return asm.Instructions{
			asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
			asm.JEq.Imm(asm.R3, dynamicAuxSentinel, failLabel),
		}, nil
	}
	if dynamicAuxLayoutOf(w.BoolField) != nil {
		return nil, fmt.Errorf("codegen: option %s.%s has no offset slot for .exists", w.BoolField.Layer.Spec.Name, w.BoolField.Aux.OutParam)
	}
	anchor, err := c.layerAnchorFor(w.BoolField.Layer)
	if err != nil {
		return nil, err
	}
	return emitAuxGating(w.BoolField.Aux.Gating, anchor, failLabel), nil
}

// genBoolValid handles `where <layer>.options.valid`: the flag the
// layer's parser walk left in its validity slot (1 parsed, 0 malformed,
// spec D-029). An absent layer is false through withLayerGuards.
func (c *whereCtx) genBoolValid(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w == nil || w.BoolField == nil || w.BoolField.Layer == nil {
		return nil, fmt.Errorf("codegen: options.valid atom lacks its layer")
	}
	slot, ok := c.queried.validSlot(w.BoolField.Layer)
	if !ok {
		return nil, fmt.Errorf("codegen: %s has no option-validity slot", w.BoolField.Layer.DisplayName())
	}
	return asm.Instructions{
		asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
		asm.JEq.Imm(asm.R3, 0, failLabel),
	}, nil
}

// genBoolEq handles `Bool == Bool` (iff) and `Bool != Bool` (xor)
// by materialising each operand once as a {0, 1} truth value in a
// register, saving the LHS to a scratch slot, then comparing the
// two. This avoids the per-packet 2× evaluation that the older
// and/or/not desugar produced (F10).
func (c *whereCtx) genBoolEq(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w == nil || w.BoolL == nil || w.BoolR == nil {
		return nil, fmt.Errorf("codegen: bool-eq lacks operands")
	}
	var jumpOp asm.JumpOp
	switch w.BoolEqOp {
	case ast.CmpEq:
		// fail when sides differ
		jumpOp = asm.JNE
	case ast.CmpNeq:
		// fail when sides agree
		jumpOp = asm.JEq
	default:
		return nil, fmt.Errorf("codegen: bool-eq with op %v not supported", w.BoolEqOp)
	}
	// Park the LHS truth value across the RHS evaluation. The RHS is a full
	// condition whose own comparison/arith codegen writes the low arith
	// scratch slots (growing up from slot 0 with its nesting), so the LHS
	// lives in the top of the arith region.
	// One slot per bool-eq nesting level: a bool-eq operand (nested
	// bool-eq) parks its own LHS one slot lower, so they never collide.
	slotDepth := maxArithDepth - 1 - c.boolEqDepth
	if slotDepth < boolEqOperandReserve {
		// Usable park slots are boolEqOperandReserve..maxArithDepth-1
		// inclusive, i.e. maxArithDepth-boolEqOperandReserve nesting levels.
		return nil, fmt.Errorf("%w: bool-eq nested deeper than %d levels", ErrNotImplemented, maxArithDepth-boolEqOperandReserve)
	}
	slot := arithStackSlot(slotDepth)

	// Operands are one level deeper so a nested bool-eq uses a lower slot.
	c.boolEqDepth++
	defer func() { c.boolEqDepth-- }()
	leftInsns, err := c.genConditionAsBool(w.BoolL)
	if err != nil {
		return nil, err
	}
	rightInsns, err := c.genConditionAsBool(w.BoolR)
	if err != nil {
		return nil, err
	}

	var insns asm.Instructions
	insns = append(insns, leftInsns...)
	insns = append(insns, asm.StoreMem(asm.R10, slot, asm.R3, asm.DWord))
	insns = append(insns, rightInsns...)
	insns = append(insns, asm.LoadMem(asm.R5, asm.R10, slot, asm.DWord))
	insns = append(insns, jumpOp.Reg(asm.R5, asm.R3, failLabel))
	return insns, nil
}

// genConditionAsBool evaluates cond once and leaves R3 ∈ {0, 1}
// reflecting whether cond was true. Internally:
//
//	inner emit (jump to `falsyLabel` on miss)
//	R3 = 1
//	Ja done
//	falsyLabel: R3 = 0
//	done:
//
// Used by genBoolEq so each operand of a Bool == Bool comparison is
// emitted exactly once.
func (c *whereCtx) genConditionAsBool(cond *ir.Condition) (asm.Instructions, error) {
	cond = foldBooleanConstants(cond)
	// A constant needs no branch diamond: its untaken arm would be
	// structurally unreachable and rejected by the BPF verifier.
	if cond != nil && cond.Kind == ast.WAtomBoolLit {
		var value int32
		if cond.BoolLitValue {
			value = 1
		}
		return asm.Instructions{asm.Mov.Imm(asm.R3, value)}, nil
	}
	falsyLabel := c.freshLabel("bool_zero")
	doneLabel := c.freshLabel("bool_done")
	inner, err := c.gen(cond, falsyLabel)
	if err != nil {
		return nil, err
	}
	var insns asm.Instructions
	insns = append(insns, inner...)
	insns = append(insns, asm.Mov.Imm(asm.R3, 1))
	insns = append(insns, asm.Ja.Label(doneLabel))
	insns = append(insns, asm.Mov.Imm(asm.R3, 0).WithSymbol(falsyLabel))
	insns = append(insns, landingNoop(doneLabel))
	return insns, nil
}

// (Earlier revisions desugared WAtomBoolEq into and/or/not via a
// helper; the precision-preserving genConditionAsBool path above
// replaces it. The algebraic form for reference:
//   iff(a, b) = (a and b) or (not a and not b)
//   xor(a, b) = (a and not b) or (not a and b))

// genAny emits a static-unroll over the quantifier's iteration
// target. Each iteration substitutes the iterator FieldRef with a
// static index and runs the inner expression. Per-iteration semantics:
//   - inner success → match found, jump past the rest of the unroll
//     into the outer (any-success) landing so where evaluation
//     continues
//   - inner failure → continue to the next iteration
//
// After all iterations have failed, control jumps to failLabel.
//
// The iteration count is capped statically by Capacity; for stacks
// with a runtime count (e.g. SRv6 segments_count = last_entry+1) the
// per-iteration prelude reads the count and skips iterations beyond
// it. Stacks without a known count source (gtp.exts / ipv6.exts)
// surface ErrNotImplemented since their actual entry count is
// dynamic without a parent field, requiring a different codegen
// strategy than static unroll.
func (c *whereCtx) genAny(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w.QuantTarget == nil {
		return nil, fmt.Errorf("codegen: any() lacks a resolved iteration target")
	}
	return c.withQuantLayerGuard(w, failLabel, func() (asm.Instructions, error) {
		if use, err := useBpfLoopAuxWalk(w); err != nil {
			return nil, err
		} else if use {
			return c.genQuantBpfLoop(w, failLabel, true)
		}
		matchLabel := c.freshLabel("any_match")
		insns, err := c.genQuantUnroll(w, matchLabel, failLabel, true)
		if err != nil {
			return nil, err
		}
		// After all iterations exhaust without a match, fall to failLabel.
		insns = append(insns, asm.Ja.Label(failLabel))
		insns = append(insns, landingNoop(matchLabel))
		return insns, nil
	})
}

// genAll emits a static-unroll where every iteration must succeed.
// Inner failure on any iteration jumps to failLabel directly; inner
// success continues to the next iteration. After all iterations
// succeed, control falls through.
func (c *whereCtx) genAll(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w.QuantTarget == nil {
		return nil, fmt.Errorf("codegen: all() lacks a resolved iteration target")
	}
	return c.withQuantLayerGuard(w, failLabel, func() (asm.Instructions, error) {
		// A stack whose header-declared count exceeds its capacity kept
		// only the first entries (spec D-029, truncated stacks): all()
		// cannot confirm the rest, so it is false.
		truncated, err := c.truncatedStackGuard(w, failLabel)
		if err != nil {
			return nil, err
		}
		insns, err := c.genAllBody(w, failLabel)
		if err != nil {
			return nil, err
		}
		return append(truncated, insns...), nil
	})
}

// truncatedStackGuard jumps to failLabel when the quantified stack's count
// comes from a header field and exceeds the stack's capacity. Empty for
// stacks counted any other way: a push count or an owner's length stops
// at the capacity by construction.
func (c *whereCtx) truncatedStackGuard(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	src, err := stackCountSource(w)
	if err != nil || src == nil || src.Stack != "" || src.Owner != nil {
		return nil, err
	}
	anchor, err := c.layerAnchorFor(src.Layer)
	if err != nil {
		return nil, err
	}
	insns := emitFieldLoad(anchor, src.ByteOff, asm.Byte)
	return append(insns,
		asm.Add.Imm(asm.R3, int32(src.Offset)),
		asm.JGT.Imm(asm.R3, int32(w.QuantTarget.Capacity), failLabel),
	), nil
}

// genAllBody is all() past the layer and truncation guards.
func (c *whereCtx) genAllBody(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if use, err := useBpfLoopAuxWalk(w); err != nil {
		return nil, err
	} else if use {
		return c.genQuantBpfLoop(w, failLabel, false)
	}
	return c.genQuantUnroll(w, "" /* no per-iter accept */, failLabel, false)
}

// withQuantLayerGuard makes any()/all() over the stack of an absentable
// layer false when the layer is absent (spec D-003 / D-007: not vacuously
// true), by guarding the layer once before the iterations; the unrolled
// atoms then skip their own guard (presentLayers). The guard also keeps
// the aux bpf_loop walk from seeding its ctx with the absent sentinel.
func (c *whereCtx) withQuantLayerGuard(w *ir.Condition, failLabel string, body func() (asm.Instructions, error)) (asm.Instructions, error) {
	// Only the layer that owns the stack: another absent layer the body
	// reads makes its own atom false, not the quantifier
	// (`all(x.f == 1 or vlan.tci == 5)`), so those atoms keep their guard
	// in each iteration.
	layer := w.QuantTarget.Layer
	guard, err := c.absentLayerGuard(layer, failLabel)
	if err != nil {
		return nil, err
	}
	if guard != nil {
		if c.presentLayers == nil {
			c.presentLayers = map[*ir.LayerInstance]bool{}
		}
		c.presentLayers[layer] = true
		defer delete(c.presentLayers, layer)
	}
	insns, err := body()
	if err != nil {
		return nil, err
	}
	return append(guard, insns...), nil
}

// hasAbsentableLayer reports whether any layer of the program can match
// zero headers, i.e. whether where atoms may need an absent-layer guard.
func (c *whereCtx) hasAbsentableLayer() bool {
	if c.absentable == nil {
		// An alternation member is absent when another member matched.
		v := c.queried.readsAltMember()
		for _, l := range c.p.Layers {
			if l != nil && l.Absentable() {
				v = true
				break
			}
		}
		c.absentable = &v
	}
	return *c.absentable
}

// absentLayerGuard jumps to failLabel when the layer matched zero headers:
// its per-layer entry slot holds layerEntryAbsent (D-003). Empty for layers
// that are always present, that an enclosing quantifier already guarded,
// or whose layer the atom does not reference at a runtime offset. A marked
// absentable layer always has a slot: the resolver marks every quantified
// layer a where / capture clause references.
//
// An alternation member is absent when another member matched: the guard
// compares the group's matched-member slot with the member's index.
func (c *whereCtx) absentLayerGuard(l *ir.LayerInstance, failLabel string) (asm.Instructions, error) {
	if l == nil || c.presentLayers[l] {
		return nil, nil
	}
	if idx, isMember := c.queried.members[l]; isMember {
		slot, ok := c.queried.matchedSlot(l.LayerPos)
		if !ok {
			return nil, fmt.Errorf("codegen: the alternation at chain position %d has no matched-member slot for a read of %q", l.LayerPos+1, l.Spec.Name)
		}
		return asm.Instructions{
			asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
			asm.JNE.Imm(asm.R3, int32(idx), failLabel),
		}, nil
	}
	if !l.Absentable() {
		return nil, nil
	}
	if !l.NeedsRuntimeOffset {
		// The resolver marks every quantified layer a where / capture
		// clause references; without the mark there is no slot to test.
		return nil, fmt.Errorf("%w: where-clause field on quantified layer %q without a runtime entry slot", ErrNotImplemented, l.Spec.Name)
	}
	slot, err := c.queried.entrySlot(l)
	if err != nil {
		return nil, err
	}
	return asm.Instructions{
		asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
		asm.JEq.Imm(asm.R3, layerEntryAbsent, failLabel),
	}, nil
}

// withLayerGuards prefixes an atom with absentLayerGuard for every distinct
// absentable layer it reads, so a field of a skipped `?` / `*` layer makes
// the atom false for `==`, `!=`, arithmetic and `.exists` alike (D-003);
// `not` of such an atom is true. The guards run before the stack guards,
// whose count reads may address the same layer's slot.
func (c *whereCtx) withLayerGuards(w *ir.Condition, failLabel string, body func(*ir.Condition, string) (asm.Instructions, error)) (asm.Instructions, error) {
	if !c.hasAbsentableLayer() {
		return body(w, failLabel)
	}
	var guards asm.Instructions
	var walkErr error
	seen := map[*ir.LayerInstance]bool{}
	ir.WalkConditionFieldRefs(w, func(ref *ir.FieldRef) {
		if walkErr != nil || ref == nil || ref.Layer == nil || seen[ref.Layer] {
			return
		}
		seen[ref.Layer] = true
		g, err := c.absentLayerGuard(ref.Layer, failLabel)
		if err != nil {
			walkErr = err
			return
		}
		guards = append(guards, g...)
	})
	if walkErr != nil {
		return nil, walkErr
	}
	insns, err := body(w, failLabel)
	if err != nil {
		return nil, err
	}
	return append(guards, insns...), nil
}

// genQuantUnroll emits Capacity copies of the inner expression, each
// with the iterator FieldRef rebound to a static index. anySemantics
// controls per-iteration jumps:
//   - true (any): inner success jumps to acceptLabel; inner failure
//     advances to the next iter via a per-iter skip landing
//   - false (all): inner failure jumps to failLabel; inner success
//     advances to the next iter
//
// For stacks that need a runtime count guard (e.g. SRv6 segments),
// the prelude on each iteration reads the count source and skips the
// per-iter body when the iter index is beyond the actual count.
func (c *whereCtx) genQuantUnroll(w *ir.Condition, acceptLabel, failLabel string, anySemantics bool) (asm.Instructions, error) {
	target := w.QuantTarget
	if target.Capacity <= 0 {
		return nil, fmt.Errorf("codegen: quantifier target capacity %d is non-positive", target.Capacity)
	}
	countSrc, err := stackCountSource(w)
	if err != nil {
		return nil, err
	}
	// A push-counted stack holds at most one inline push plus one per
	// walk iteration; entries past that bound never exist.
	n := target.Capacity
	if countSrc != nil && countSrc.Stack != "" {
		n = min(n, pushBound(target.Layer.Spec, countSrc.Stack))
	}
	var insns asm.Instructions
	for i := 0; i < n; i++ {
		iterSkip := c.freshLabel("quant_skip")
		// Per-iteration runtime count guard: when present, skip the
		// body for iter ≥ count. The check is `count <= i → skip`,
		// equivalent to the "out-of-bounds" branch.
		if countSrc != nil {
			guard, err := c.emitCountGuard(countSrc, i, iterSkip)
			if err != nil {
				return nil, err
			}
			insns = append(insns, guard...)
		}
		body, err := c.genQuantIterBody(w.Inner, target, i, acceptLabel, failLabel, iterSkip, anySemantics)
		if err != nil {
			return nil, err
		}
		insns = append(insns, body...)
		insns = append(insns, landingNoop(iterSkip))
	}
	return insns, nil
}

// pushBound is the most entries a parser machine can push onto `stack`
// (vocab.ProtocolSpec.StackPushBound).
func pushBound(spec *vocab.ProtocolSpec, stack string) int {
	return spec.StackPushBound(stack)
}


// genQuantIterBody clones the inner condition with the iterator
// FieldRef rebound to a static index for this iteration, then emits
// it. The fail target depends on anySemantics:
//   - any: per-iter mismatch → iterSkip (= "try next iter")
//   - all: per-iter mismatch → failLabel (= "all() fails")
//
// On success:
//   - any: emit a Ja to acceptLabel after the body so the unroll
//     short-circuits
//   - all: fall through to next iteration (no extra jump)
func (c *whereCtx) genQuantIterBody(inner *ir.Condition, target *ir.QuantTarget, idx int, acceptLabel, failLabel, iterSkip string, anySemantics bool) (asm.Instructions, error) {
	rebound, err := rebindIterator(inner, target, uint64(idx))
	if err != nil {
		return nil, err
	}
	var perIterFail string
	if anySemantics {
		perIterFail = iterSkip
	} else {
		perIterFail = failLabel
	}
	body, err := c.gen(rebound, perIterFail)
	if err != nil {
		return nil, err
	}
	if anySemantics {
		body = append(body, asm.Ja.Label(acceptLabel))
	}
	return body, nil
}

// withStackGuards prefixes an atom with a count guard for every static
// stack index it reads (`srv6.segments[2].addr`, `tcp.options.SACK.blocks[1]`):
// an entry past the stack's runtime count is absent, so the atom is false
// for `==`, `!=`, ordered compares and arithmetic alike (spec D-031).
// Stacks without a count source keep their capacity-only bounds. An
// entry referenced more than once in the atom is guarded once; an index
// the any/all unroll rebound from its iterator is already guarded by
// the unroll (StackIndex.Guarded).
func (c *whereCtx) withStackGuards(w *ir.Condition, failLabel string, body func(*ir.Condition, string) (asm.Instructions, error)) (asm.Instructions, error) {
	var guards asm.Instructions
	var walkErr error
	guarded := map[string]bool{}
	ir.WalkConditionFieldRefs(w, func(ref *ir.FieldRef) {
		if walkErr != nil || ref == nil || ref.Aux == nil || ref.Aux.Stack == nil || !ref.Aux.Stack.IsStatic || ref.Aux.Stack.Guarded {
			return
		}
		key := fmt.Sprintf("%p/%s/%d", ref.Layer, ref.Aux.OutParam, ref.Aux.Stack.Static)
		if guarded[key] {
			return
		}
		guarded[key] = true
		src, err := refCountSource(ref)
		if err != nil || src == nil {
			walkErr = err
			return
		}
		g, err := c.emitCountGuard(src, int(ref.Aux.Stack.Static), failLabel)
		if err != nil {
			walkErr = err
			return
		}
		guards = append(guards, g...)
	})
	if walkErr != nil {
		return nil, walkErr
	}
	insns, err := body(w, failLabel)
	if err != nil {
		return nil, err
	}
	return append(guards, insns...), nil
}

// refCountSource derives the runtime element count of the stack a
// reference indexes. Option-internal arrays (SACK blocks, RR addrs) use
// the owner option's length byte: it sits at byte 1 by RFC convention
// (kind = byte 0), SubBefore = OffsetAfterOwner (the option's fixed
// prefix) is subtracted, and the residue divides by the element size:
//
//	SACK (OffsetAfterOwner=2, ElemSize=8): (length-2) >> 3 = 0..4 blocks
//	RR   (OffsetAfterOwner=3, ElemSize=4): (length-3) >> 2 = 0..9 addrs
//
// Declare-only stacks with @kunai_stack_count read a primary-header byte.
// Stacks the parser machine pushes onto (ipv6.exts, gtp.exts) read the
// push count slot the machine maintains. nil when the stack has no count
// source (callers fall back to Capacity).
func refCountSource(ref *ir.FieldRef) (*quantCountSource, error) {
	if ref.Aux.OwnerOption != nil {
		shift := log2PowerOfTwo(ref.Aux.HeaderSize)
		if shift < 0 {
			return nil, fmt.Errorf("codegen: stack element size %d is not a power of two (cannot derive count via shift)", ref.Aux.HeaderSize)
		}
		return &quantCountSource{Layer: ref.Layer, Owner: ref.Aux.OwnerOption, ByteOff: 1, SubBefore: ref.Aux.OffsetAfterOwner, RShAfter: shift}, nil
	}
	if cnt := ref.Layer.Spec.StackCounts[ref.Aux.OutParam]; cnt != nil {
		return &quantCountSource{Layer: ref.Layer, ByteOff: cnt.ByteOff, Offset: cnt.Addend}, nil
	}
	if needsPushCount(ref) {
		return &quantCountSource{Layer: ref.Layer, Stack: ref.Aux.OutParam}, nil
	}
	return nil, nil
}

// emitCountGuard emits the per-iteration check that the iteration
// index is below the runtime count. Primary-header byte (Owner == nil)
// reads from a layer-anchored field; owner-slot (Owner != nil) reads
// from the option's per-packet base via the dynamic-aux slot, with
// sentinel = option absent translating to "skip every iter" (vacuous
// any/all).
func (c *whereCtx) emitCountGuard(countSrc *quantCountSource, idx int, skipLabel string) (asm.Instructions, error) {
	if countSrc.Stack != "" {
		slot, ok := c.queried.stackCountSlot(countSrc.Layer, countSrc.Stack)
		if !ok {
			return nil, fmt.Errorf("codegen: push count of stack %q not in demand set", countSrc.Stack)
		}
		return asm.Instructions{
			asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
			asm.JLE.Imm(asm.R3, int32(idx), skipLabel),
		}, nil
	}
	if countSrc.Owner != nil {
		slot, ok := c.queried.dynamicAuxSlotForLayout(countSrc.Layer, countSrc.Owner)
		if !ok {
			return nil, fmt.Errorf("codegen: quantifier owner option %q not in demand set", countSrc.Owner.OutParam)
		}
		insns := emitDynamicAuxByteLoad(slot, countSrc.ByteOff, asm.Byte, skipLabel)
		insns = append(insns,
			asm.JLT.Imm(asm.R3, int32(countSrc.SubBefore), skipLabel),
			asm.Sub.Imm(asm.R3, int32(countSrc.SubBefore)),
			asm.RSh.Imm(asm.R3, int32(countSrc.RShAfter)),
			asm.JLE.Imm(asm.R3, int32(idx), skipLabel),
		)
		return insns, nil
	}
	anchor, err := c.layerAnchorFor(countSrc.Layer)
	if err != nil {
		return nil, err
	}
	insns := emitFieldLoad(anchor, countSrc.ByteOff, asm.Byte)
	insns = append(insns,
		asm.Add.Imm(asm.R3, int32(countSrc.Offset)),
		// `if R3 <= idx: skip` → `if R3 < idx+1: skip` → JLE.Imm(R3, idx, skip).
		asm.JLE.Imm(asm.R3, int32(idx), skipLabel),
	)
	return insns, nil
}

// quantCountSource carries the runtime count of an aux header stack.
// Three shapes folded into one struct so emitCountGuard can dispatch on
// Stack / Owner:
//   - Primary-header byte: Layer + ByteOff + Offset (e.g. SRv6
//     last_entry at byte 4, count = last_entry + 1).
//   - Owner option slot: Owner (the AuxLayout the slot maps to) +
//     ByteOff (= byte position of the length field within the
//     option, e.g. 1 for SACK) + SubBefore (bytes to subtract = the
//     option's fixed prefix size including kind+length) + RShAfter
//     (log2 of element size, e.g. 3 for 8-byte SACK blocks).
//   - Push count slot: Stack names the out-stack whose demand slot the
//     parser machine increments on every `extract(stack.next)`.
type quantCountSource struct {
	Layer     *ir.LayerInstance
	Owner     *vocab.AuxLayout
	Stack     string
	ByteOff   int
	Offset    int // primary-header path: value to add to the loaded byte
	SubBefore int // owner-slot path: bytes subtracted before the right shift
	RShAfter  int // owner-slot path: log2(elem_size) — divides residue into element count
}

// stackCountSource derives a runtime count for the quantifier
// target's stack. Option-internal arrays (B-4 SACK blocks) use the
// owner-slot path with the option's length byte. Declare-only aux
// stacks with a @kunai_stack_count annotation use the primary-header
// path (Spec.StackCounts entry; SRv6 segments are the canonical
// example via `field=last_entry, offset=1`). Other stacks return nil
// so the unroll runs over the full Capacity (which is safe for
// self-flag chains where the parser has already walked every entry).
func stackCountSource(w *ir.Condition) (*quantCountSource, error) {
	var iterRef *ir.FieldRef
	ir.WalkConditionFieldRefs(w.Inner, func(ref *ir.FieldRef) {
		if iterRef == nil && ref != nil && ref.Aux != nil && ref.Aux.Stack != nil && ref.Aux.Stack.IsIterator {
			iterRef = ref
		}
	})
	if iterRef == nil {
		return nil, fmt.Errorf("codegen: quantifier inner has no iterator field reference")
	}
	return refCountSource(iterRef)
}

// rebindIterator deep-copies the inner condition, replacing every
// iterator FieldRef with a static-index FieldRef pinned at idx. The
// returned condition is independent so the original IR can be reused
// across iterations without state leak.
func rebindIterator(inner *ir.Condition, target *ir.QuantTarget, idx uint64) (*ir.Condition, error) {
	if inner == nil {
		return nil, fmt.Errorf("codegen: quantifier inner is nil")
	}
	cloned, err := cloneConditionWithRebind(inner, target, idx)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func cloneConditionWithRebind(c *ir.Condition, target *ir.QuantTarget, idx uint64) (*ir.Condition, error) {
	if c == nil {
		return nil, nil
	}
	cp := *c
	if c.LiteralField != nil {
		ref, err := rebindFieldRef(c.LiteralField, target, idx)
		if err != nil {
			return nil, err
		}
		cp.LiteralField = ref
	}
	if c.ArithL != nil {
		al, err := cloneArithWithRebind(c.ArithL, target, idx)
		if err != nil {
			return nil, err
		}
		cp.ArithL = al
	}
	if c.ArithR != nil {
		ar, err := cloneArithWithRebind(c.ArithR, target, idx)
		if err != nil {
			return nil, err
		}
		cp.ArithR = ar
	}
	if c.Left != nil {
		l, err := cloneConditionWithRebind(c.Left, target, idx)
		if err != nil {
			return nil, err
		}
		cp.Left = l
	}
	if c.Right != nil {
		r, err := cloneConditionWithRebind(c.Right, target, idx)
		if err != nil {
			return nil, err
		}
		cp.Right = r
	}
	if c.Inner != nil {
		i, err := cloneConditionWithRebind(c.Inner, target, idx)
		if err != nil {
			return nil, err
		}
		cp.Inner = i
	}
	return &cp, nil
}

func cloneArithWithRebind(a *ir.ArithExpr, target *ir.QuantTarget, idx uint64) (*ir.ArithExpr, error) {
	if a == nil {
		return nil, nil
	}
	cp := *a
	if a.Kind == ast.ArithField && a.Field != nil {
		ref, err := rebindFieldRef(a.Field, target, idx)
		if err != nil {
			return nil, err
		}
		cp.Field = ref
	}
	if a.Left != nil {
		l, err := cloneArithWithRebind(a.Left, target, idx)
		if err != nil {
			return nil, err
		}
		cp.Left = l
	}
	if a.Right != nil {
		r, err := cloneArithWithRebind(a.Right, target, idx)
		if err != nil {
			return nil, err
		}
		cp.Right = r
	}
	return &cp, nil
}

// layerName describes a layer for error messages: "ipv6", or
// "ipv6@inner" when labelled. Nil-safe.
func layerName(l *ir.LayerInstance) string {
	if l == nil || l.Spec == nil {
		return "?"
	}
	if l.Label != "" {
		return l.Spec.Name + "@" + l.Label
	}
	return l.Spec.Name
}

func rebindFieldRef(ref *ir.FieldRef, target *ir.QuantTarget, idx uint64) (*ir.FieldRef, error) {
	if ref == nil || ref.Aux == nil || ref.Aux.Stack == nil || !ref.Aux.Stack.IsIterator {
		return ref, nil
	}
	// Stack identity is (owning layer, out param): distinct layers can
	// expose a stack under the same name (ipv6 and gtp both declare
	// `exts`), so the layer must match too. The resolver already
	// rejects multi-stack quantifiers (findQuantTarget); this guards
	// the same invariant at the codegen boundary.
	if ref.Layer != target.Layer || ref.Aux.OutParam != target.OutParam {
		return nil, fmt.Errorf("codegen: iterator FieldRef references stack %s.%s but quantifier target is %s.%s",
			layerName(ref.Layer), ref.Aux.OutParam, layerName(target.Layer), target.OutParam)
	}
	cp := *ref
	auxCopy := *ref.Aux
	auxCopy.Stack = &ir.StackIndex{
		Capacity: target.Capacity,
		IsStatic: true,
		Static:   idx,
		Guarded:  true,
	}
	cp.Aux = &auxCopy
	return &cp, nil
}

// genAnd: both sides must succeed. Either failure jumps to failLabel.
func (c *whereCtx) genAnd(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	left, err := c.gen(w.Left, failLabel)
	if err != nil {
		return nil, err
	}
	right, err := c.gen(w.Right, failLabel)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

// genOr: left success skips right (short-circuit accept); otherwise
// try right with the caller's failLabel.
//
//	<left with failLabel = tryRight>
//	Ja orDone
//	tryRight: <right with failLabel = failLabel>
//	orDone: <landing symbol>
func (c *whereCtx) genOr(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	tryRight := c.freshLabel("or_right")
	orDone := c.freshLabel("or_done")

	left, err := c.gen(w.Left, tryRight)
	if err != nil {
		return nil, err
	}
	right, err := c.gen(w.Right, failLabel)
	if err != nil {
		return nil, err
	}
	if len(right) == 0 {
		return nil, fmt.Errorf("codegen: or right side produced no instructions")
	}
	// Attach tryRight to the first instruction of right. If that
	// instruction already owns a symbol something higher up is
	// double-labelling — fail loudly so the bug is obvious rather
	// than silently clobbering the earlier label.
	if sym := right[0].Symbol(); sym != "" {
		return nil, fmt.Errorf("codegen: or right side already carries symbol %q", sym)
	}
	right[0] = right[0].WithSymbol(tryRight)

	var insns asm.Instructions
	insns = append(insns, left...)
	insns = append(insns, asm.Ja.Label(orDone))
	insns = append(insns, right...)
	insns = append(insns, landingNoop(orDone))
	return insns, nil
}

// genNot: inner success means "not" fails; inner failure means "not"
// succeeds.
//
//	<inner with failLabel = notSucc>
//	Ja failLabel    # inner succeeded → not fails
//	notSucc: <landing symbol>
func (c *whereCtx) genNot(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	notSucc := c.freshLabel("not_succ")
	inner, err := c.gen(w.Inner, notSucc)
	if err != nil {
		return nil, err
	}
	var insns asm.Instructions
	insns = append(insns, inner...)
	insns = append(insns, asm.Ja.Label(failLabel))
	insns = append(insns, landingNoop(notSucc))
	return insns, nil
}

// --- Arithmetic comparison ---

// arithStackBase is the first stack offset (from R10) used to save the
// left operand of a binary op while the right operand is evaluated.
// The 8-byte slots extend downward (arithStackBase - depth*8). Bounds
// enforced by maxArithDepth keep the total arithmetic scratch area
// well inside the 512-byte BPF stack and well above the slots
// runFilter itself owns (-8 through -48).
//
// Slot allocation (each path "owns" its slots while it executes):
//
//   - 0..15: 64-bit arith stack — a binary node at depth d parks its
//     left operand in slot d and evaluates both children from depth
//     d+1. A 64-bit comparison parks its left value in the first slot
//     the right side leaves free (slot 0 when the right side is a plain
//     operand).
//   - The 128-bit path keeps slots 0..4 (arith128ReservedSlots) for its
//     own preserves: 0,1 for genArithCompare128's LHS hold, 2,3 for
//     genArith128's `field + field` LHS hi/lo, and 4 for
//     genArithField128Load's high-half transient stash. A `x ± y` whose
//     both sides park in 2,3 holds its left result in the next two slots
//     from 5 up, one pair per such enclosing node (whereCtx.wideHold). A
//     sub-64-bit expression inside it (genArith128Narrow) runs the
//     64-bit pipeline from 5 + wideHold up, so none of them share a slot.
//
// genBoolEq also parks LHS truth values in this region, growing *down*
// from slot 15 (one per bool-eq nesting level) while operand arith grows
// *up* from slot 0. The two are kept disjoint by three guards: bool-eq
// park slots can't drop below boolEqOperandReserve (protecting the
// 128-bit path's fixed low slots), genArithWithBits caps operand arith
// depth at maxArithDepth-boolEqDepth (protecting the parked slots from a
// deep `+`/`-` chain), and genArith128BothPark refuses a hold pair that
// would reach the same ceiling. Without the latter, a bool-eq operand arith chain
// reaching slot 15 would overwrite the saved LHS and silently mis-compare.
//
// The deepest slot (slot 15 at -176) writes bytes [-176, -168) and
// abuts bpfLoopCtxLayerEntrySlot's range [-184, -176) without
// overlap.
const (
	arithStackBase = -56
	maxArithDepth  = 16
	// boolEqOperandReserve is how many low arith slots a single bool-eq
	// operand compare always consumes (slots 0..4 for a 128-bit compare;
	// hold pairs above them are checked against the park ceiling as they
	// are taken).
	// genBoolEq parks its LHS in the top of the arith region growing
	// downward one slot per nesting level, so it must stay above these
	// reserved low slots; deeper bool-eq nesting is rejected.
	boolEqOperandReserve = arith128ReservedSlots
)

// arithCmpTargetBits returns the comparison's effective integer
// width: the wider of the two operands' field widths, or 0 if both
// sides are pure-literal (no field references). Mirrors
// resolve/typing.go::arithCmpTargetBits but lives here too because
// codegen cannot import resolve.
func arithCmpTargetBits(l, r *ir.ArithExpr) int {
	lb := arithMaxFieldBits(l)
	rb := arithMaxFieldBits(r)
	if lb > rb {
		return lb
	}
	return rb
}

// arithMaxFieldBits walks an arith subtree and returns the largest
// effective bit width of any field reference encountered (slice-
// adjusted). Returns 0 if the subtree is pure-literal.
func arithMaxFieldBits(e *ir.ArithExpr) int {
	if e == nil {
		return 0
	}
	switch e.Kind {
	case ast.ArithField:
		return e.Field.EffectiveBits()
	case ast.ArithBinOp:
		l := arithMaxFieldBits(e.Left)
		r := arithMaxFieldBits(e.Right)
		if l > r {
			return l
		}
		return r
	}
	return 0
}

// genArithCompare emits code for "arith CmpOp arith". Left operand
// ends up in R5, right in R3; the reject-direction jump covers the
// failure branch.
func (c *whereCtx) genArithCompare(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	// Compute the comparison's target width per dsl-types.md §5.2 so
	// integer literals can be narrowed via 2's-complement on the way
	// to the BPF int32 immediate. Without this, `tcp.dport == -1`
	// stores the constant as 0xffff..ff and trips the immediate
	// range check; the spec wants it narrowed to bit<16> = 0xffff.
	targetBits := arithCmpTargetBits(w.ArithL, w.ArithR)
	saved := c.atomFail
	c.atomFail = failLabel
	defer func() { c.atomFail = saved }()
	if targetBits > 64 {
		return c.genArithCompare128(w, failLabel, targetBits)
	}
	left, err := c.genArithWithBits(w.ArithL, 0, targetBits)
	if err != nil {
		return nil, err
	}
	right, err := c.genArithWithBits(w.ArithR, 0, targetBits)
	if err != nil {
		return nil, err
	}
	jumpOp, ok := rejectingJumpOp(w.Op)
	if !ok {
		return nil, fmt.Errorf("codegen: unknown comparison op %v", w.Op)
	}

	// The left value is parked while the right side is computed, in the
	// first slot the right side's binary nodes do not use (they take
	// slots 0..nesting-1): slot 0 for a plain operand, as before.
	// (Generating the right side above already refused a nesting that
	// would leave no slot.)
	slot := arithStackSlot(arithNesting(w.ArithR))
	var insns asm.Instructions
	insns = append(insns, left...)
	insns = append(insns, asm.StoreMem(asm.R10, slot, asm.R3, asm.DWord))
	insns = append(insns, right...)
	insns = append(insns, asm.LoadMem(asm.R5, asm.R10, slot, asm.DWord))
	insns = append(insns, jumpOp.Reg(asm.R5, asm.R3, failLabel))
	return insns, nil
}

// genArithCompare128 handles where-arith comparisons whose effective
// width is > 64 bits — i.e. an Int<128> (= IPv6 address) reaches the
// arith path. The 64-bit pipeline can't load these in one shot, so
// we emit a register-pair pipeline where each side leaves
// R3 = high half, R5 = low half. Supported ops: `==` / `!=` (F4) and
// `<` / `≤` / `>` / `≥` (F3). Operand shapes supported: ArithField
// (an Int<128> field), a constant, `x ± const` and `x ± y` nested on
// either side, and any sub-64-bit expression, which computes in 64 bits
// and joins zero-extended (see genArith128); a ± whose both sides park
// holds its left result above the reserved slots (genArith128BothPark).
// A slice between 65 and 127 bits and Int<128> aux fields return
// ErrNotImplemented; operators
// other than + and - on Int<128> operands never arrive, the resolver
// types them as errors (dsl-types.md §13.9).
func (c *whereCtx) genArithCompare128(w *ir.Condition, failLabel string, targetBits int) (asm.Instructions, error) {
	// Mid-width slice cmps (widths in (64, 128) other than exactly
	// 128) are desugared in the resolver into chains of single-LDX
	// sub-cmps, so we should only see `targetBits == 128` here. A
	// width that slipped past the desugar is either an arith binop
	// (operand width > 64) or a non-slice 128-bit field — both go
	// through the dual-LDX pipeline below.
	if targetBits != 128 {
		return nil, fmt.Errorf("%w: bit<%d> arith cmp in where-path needs a mid-width pipeline that hasn't been wired (resolver should have desugared this; see tryDesugarMultiLDXSliceCmp)", ErrNotImplemented, targetBits)
	}
	leftInsns, err := c.genArith128(w.ArithL)
	if err != nil {
		return nil, err
	}
	rightInsns, err := c.genArith128(w.ArithR)
	if err != nil {
		return nil, err
	}
	// kunai owns only R3 / R5; R6/R7/R8 are host-callee-saved and
	// R9 is the host's pkt_len that captureWithXdpOutput reads after
	// filter eval. The dual-half compare therefore parks rhs_low to
	// a kunai-owned slot instead of an alternate register, and shape
	// mirrors bracket-side emitIPv6OrderedCmp (R5=lhs half, R3=rhs
	// half) for the per-op jump table reuse.
	lhsHighSlot := arithStackSlot(0)
	lhsLowSlot := arithStackSlot(1)
	rhsLowSlot := arithStackSlot(2)
	var insns asm.Instructions
	insns = append(insns, leftInsns...)
	insns = append(insns, asm.StoreMem(asm.R10, lhsHighSlot, asm.R3, asm.DWord))
	insns = append(insns, asm.StoreMem(asm.R10, lhsLowSlot, asm.R5, asm.DWord))
	insns = append(insns, rightInsns...)
	// R3 = rhs_high, R5 = rhs_low.
	insns = append(insns, asm.StoreMem(asm.R10, rhsLowSlot, asm.R5, asm.DWord))
	insns = append(insns, asm.LoadMem(asm.R5, asm.R10, lhsHighSlot, asm.DWord)) // R5 = lhs_high
	reloadLows := asm.Instructions{
		asm.LoadMem(asm.R3, asm.R10, lhsLowSlot, asm.DWord),
		asm.LoadMem(asm.R5, asm.R10, rhsLowSlot, asm.DWord),
	}
	switch w.Op {
	case ast.CmpEq:
		insns = append(insns, asm.JNE.Reg(asm.R5, asm.R3, failLabel))
		insns = append(insns, reloadLows...)
		insns = append(insns, asm.JNE.Reg(asm.R3, asm.R5, failLabel))
	case ast.CmpNeq:
		// Per-cmp landing lets the high-mismatch path short-circuit
		// past the low-half check.
		matchLabel := c.freshLabel("ne128_match")
		insns = append(insns, asm.JNE.Reg(asm.R5, asm.R3, matchLabel))
		insns = append(insns, reloadLows...)
		insns = append(insns, asm.JEq.Reg(asm.R3, asm.R5, failLabel))
		insns = append(insns, landingNoop(matchLabel))
	case ast.CmpLt, ast.CmpLe, ast.CmpGt, ast.CmpGe:
		// Lex compare: high decides if strictly inequal; equal falls
		// through to the low-half miss check. Recipe matches
		// emitIPv6OrderedCmp; jump tables shared.
		matchLabel := c.freshLabel("lt128_match")
		highSuccess, highFail := highHalfJumps(w.Op)
		lowMiss := lowHalfMissJump(w.Op)
		insns = append(insns, highSuccess.Reg(asm.R5, asm.R3, matchLabel))
		insns = append(insns, highFail.Reg(asm.R5, asm.R3, failLabel))
		insns = append(insns, reloadLows...)
		insns = append(insns, lowMiss.Reg(asm.R3, asm.R5, failLabel))
		insns = append(insns, landingNoop(matchLabel))
	default:
		return nil, fmt.Errorf("codegen: unknown cmp op %v in 128-bit where-arith", w.Op)
	}
	return insns, nil
}

// genArith128 emits insns that leave R3=high and R5=low of an Int<128>
// arith expression. Supported shapes:
//
//   - a sub-64-bit expression (a narrower field, a slice of at most 64
//     bits, `tcp.dport * 2`): the 64-bit pipeline, zero-extended
//     (genArith128Narrow)
//   - ArithField: 16-byte field load via genArithField128Load
//   - ArithConst: literal materialised as (0, const), or all ones in the
//     high half for a negative literal (-1 is 2^128 - 1 at this width)
//   - ArithBinOp with op ∈ {+, -}:
//   - `field op const`: const folded into low half, carry/borrow
//     propagated to high via a const-relative compare (no register
//     beyond R3/R5 needed).
//   - `field op field`: LHS preserved in arith slots 2/3 while RHS
//     is computed, then RHS is the in-place accumulator that LHS
//     gets added/subtracted into. A RHS that needs those slots
//     itself goes first (genArith128FieldOpField); when both sides
//     need them, the left result is held above the reserved slots
//     (genArith128BothPark).
//
// Other operators are typing errors above 64 bits (dsl-types.md §13.9),
// so the resolver never lets them reach here.
func (c *whereCtx) genArith128(e *ir.ArithExpr) (asm.Instructions, error) {
	if e == nil {
		return nil, fmt.Errorf("codegen: nil 128-bit arith expression")
	}
	// A subexpression whose fields are all at most 64 bits wide (a
	// narrower field, a slice, `tcp.dport * 2`) computes in 64 bits like
	// anywhere else (§13.9) and joins the 128-bit operand zero-extended.
	if isNarrowArith(e) {
		return c.genArith128Narrow(e)
	}
	switch e.Kind {
	case ast.ArithField:
		if f := e.Field; f != nil && f.Field != nil && (f.Slice != nil || f.Field.Bits != 128) {
			return nil, fmt.Errorf("%w: %s.%s (bit<%d>) next to an Int<128> operand: a field wider than 64 bits but narrower than 128 is not wired", ErrNotImplemented, f.Layer.Spec.Name, f.Field.Name, f.EffectiveBits())
		}
		return c.genArithField128Load(e.Field)
	case ast.ArithBinOp:
		if e.Op != ast.ArithAdd && e.Op != ast.ArithSub {
			return nil, fmt.Errorf("codegen: %s on Int<128> operands reached codegen; the resolver should have rejected it", e.Op)
		}
		if e.Right == nil {
			return nil, fmt.Errorf("codegen: bit<128> arith binop missing RHS")
		}
		if e.Right.Kind == ast.ArithConst {
			return c.genArith128FieldOpConst(e)
		}
		return c.genArith128FieldOpField(e)
	case ast.ArithConst:
		// A positive constant is (0, const): the resolver fit-checked it
		// against Int<128>, so only the low half can be non-zero. A
		// negative literal is the 128-bit two's complement, so its high
		// half is all ones (Const already holds the 64-bit low half);
		// `-0` is 0.
		high := int32(0)
		if e.Negative && int64(e.Const) < 0 {
			high = -1
		}
		return append(asm.Instructions{asm.Mov.Imm(asm.R3, high)}, loadConst(asm.R5, e.Const)...), nil
	}
	return nil, fmt.Errorf("%w: bit<128> arith expression kind %v not supported", ErrNotImplemented, e.Kind)
}

// isNarrowArith reports whether `e` is an expression the 64-bit pipeline
// evaluates: a field or a binary node none of whose fields is wider than
// 64 bits (a node of literals only computes in 64 bits too, D-009). A
// bare constant is not narrow; it takes its width from the operand next
// to it.
func isNarrowArith(e *ir.ArithExpr) bool {
	return e != nil && e.Kind != ast.ArithConst && arithMaxFieldBits(e) <= 64
}

// arithNesting is the number of arith slots `e` needs: one per level of
// binary nodes.
func arithNesting(e *ir.ArithExpr) int {
	if e == nil || e.Kind != ast.ArithBinOp {
		return 0
	}
	return 1 + max(arithNesting(e.Left), arithNesting(e.Right))
}

// arith128ReservedSlots is how many low arith slots the 128-bit path
// parks operands in while the other operand is computed: the compare's
// left side in 0/1, field ± field's first operand in 2/3, the high-half
// stash in 4. A sub-64-bit expression inside it, and the bool-eq park
// slots (boolEqOperandReserve), stay above them.
const arith128ReservedSlots = 5

// parks128 reports whether evaluating `e` in the 128-bit path parks an
// operand in slots 2/3: a `x ± y` whose right side is not a constant
// (genArith128FieldOpField), directly or under `± const` nodes. It
// follows genArith128's dispatch and has to change with it.
func parks128(e *ir.ArithExpr) bool {
	if e == nil || e.Kind != ast.ArithBinOp || isNarrowArith(e) {
		return false
	}
	if e.Right != nil && e.Right.Kind == ast.ArithConst {
		return parks128(e.Left)
	}
	return true
}

// genArith128Narrow evaluates a sub-64-bit expression with the 64-bit
// pipeline and leaves it zero-extended in the 128-bit pair (R3 = 0,
// R5 = value). It starts above the slots the 128-bit path parks its
// operands in (arith128ReservedSlots) and the hold pairs of enclosing
// both-sides nodes (wideHold), which leaves it that many fewer nesting
// levels than a 64-bit comparison has.
func (c *whereCtx) genArith128Narrow(e *ir.ArithExpr) (asm.Instructions, error) {
	// Its leaves sit at depth base + nesting, which must stay below the
	// arith ceiling.
	base := arith128ReservedSlots + c.wideHold
	if room := maxArithDepth - c.boolEqDepth - base; arithNesting(e) >= room {
		return nil, fmt.Errorf("%w: a sub-64-bit expression next to an Int<128> operand nests deeper than %d levels", ErrNotImplemented, room-1)
	}
	insns, err := c.genArithWithBits(e, base, 0)
	if err != nil {
		return nil, err
	}
	return append(insns, asm.Mov.Reg(asm.R5, asm.R3), asm.Mov.Imm(asm.R3, 0)), nil
}

// genArith128BothPark is `x ± y` where both sides park an operand in
// slots 2/3 themselves (`(a + b) - (c + d)`). The left result is held in
// the next two slots above arith128ReservedSlots and the ones enclosing
// nodes of this kind hold (wideHold), the right side is computed with
// those slots taken, and the left result then moves to slots 2/3 so the
// ordinary combine runs. Only these nodes take extra slots, so other
// expressions keep every nesting level they had.
func (c *whereCtx) genArith128BothPark(e *ir.ArithExpr) (asm.Instructions, error) {
	hold := arith128ReservedSlots + c.wideHold
	if hold+2 > maxArithDepth-c.boolEqDepth {
		return nil, fmt.Errorf("%w: bit<128> arith nests 128-bit expressions on both sides of %s too deeply", ErrNotImplemented, e.Op)
	}
	leftInsns, err := c.genArith128(e.Left)
	if err != nil {
		return nil, err
	}
	c.wideHold += 2
	rightInsns, err := c.genArith128(e.Right)
	c.wideHold -= 2
	if err != nil {
		return nil, err
	}
	holdHigh, holdLow := arithStackSlot(hold), arithStackSlot(hold+1)
	insns := append(asm.Instructions{}, leftInsns...)
	insns = append(insns,
		asm.StoreMem(asm.R10, holdHigh, asm.R3, asm.DWord),
		asm.StoreMem(asm.R10, holdLow, asm.R5, asm.DWord),
	)
	insns = append(insns, rightInsns...)
	// Left into slots 2/3 (R2 is scratch), right stays in R3/R5.
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R10, holdHigh, asm.DWord),
		asm.StoreMem(asm.R10, arithStackSlot(2), asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.R10, holdLow, asm.DWord),
		asm.StoreMem(asm.R10, arithStackSlot(3), asm.R2, asm.DWord),
	)
	combine, err := c.genArith128Combine(e.Op)
	if err != nil {
		return nil, err
	}
	return append(insns, combine...), nil
}

// genArith128FieldOpConst handles `field + const` / `field - const`
// at Int<128>. Low half gets the immediate ALU; carry / borrow to
// high is detected by comparing the new low against the constant
// itself, eliminating the need for a register-saved orig value.
//
// Why constant-relative compare works (unsigned 64-bit add):
//   - new = (orig + const) mod 2^64
//   - no wrap ⇒ new ≥ const  (since orig ≥ 0)
//   - wrap   ⇒ new <  const  (since orig + const ≥ 2^64 implies
//     new = orig + const − 2^64 < const)
//
// Sub mirrors the relation: borrow ⇔ orig < const, checked before
// the subtraction so the test sees the unwrapped low half.
//
// A negative literal is the operator flipped onto its magnitude
// (`x + -1` is `x - 1` modulo 2^128), so the constant folded into the
// low half is always the literal's absolute value. A constant above the
// int32 immediate range goes through R2 (caller-saved scratch, free
// inside the where pipeline) with the register forms of the same three
// instructions.
func (c *whereCtx) genArith128FieldOpConst(e *ir.ArithExpr) (asm.Instructions, error) {
	imm, op := e.Right.Const, e.Op
	if e.Right.Negative {
		imm = -imm // two's complement magnitude
		if op == ast.ArithAdd {
			op = ast.ArithSub
		} else {
			op = ast.ArithAdd
		}
	}
	leftInsns, err := c.genArith128(e.Left)
	if err != nil {
		return nil, err
	}
	insns := append(asm.Instructions{}, leftInsns...)
	wide := imm > 0x7FFFFFFF
	if wide {
		insns = append(insns, loadConst(asm.R2, imm)...)
	}
	alu := func(op asm.ALUOp) asm.Instruction {
		if wide {
			return op.Reg(asm.R5, asm.R2)
		}
		return op.Imm(asm.R5, int32(imm))
	}
	geConst := func(label string) asm.Instruction {
		if wide {
			return asm.JGE.Reg(asm.R5, asm.R2, label)
		}
		return asm.JGE.Imm(asm.R5, int32(imm), label)
	}
	switch op {
	case ast.ArithAdd:
		insns = append(insns, alu(asm.Add))
		noCarry := c.freshLabel("v128_nocarry")
		insns = append(insns, geConst(noCarry))
		insns = append(insns, asm.Add.Imm(asm.R3, 1))
		insns = append(insns, landingNoop(noCarry))
	case ast.ArithSub:
		noBorrow := c.freshLabel("v128_noborrow")
		insns = append(insns, geConst(noBorrow))
		insns = append(insns, asm.Sub.Imm(asm.R3, 1))
		insns = append(insns, landingNoop(noBorrow))
		insns = append(insns, alu(asm.Sub))
	}
	return insns, nil
}

// loadConst puts a 64-bit constant into dst: one Mov when the bit pattern
// is a sign-extended int32 (BPF MOV64 sign-extends its immediate, so small
// negative two's-complement values take the short form too), else the
// two-slot 64-bit load.
func loadConst(dst asm.Register, value uint64) asm.Instructions {
	if v := int64(value); v >= math.MinInt32 && v <= math.MaxInt32 {
		return asm.Instructions{asm.Mov.Imm(dst, int32(v))}
	}
	return asm.Instructions{asm.LoadImm(dst, int64(value), asm.DWord)}
}

// genArith128FieldOpField handles `field op field` at Int<128>. LHS
// is parked in arith slots 2/3 while RHS is computed; then we fold
// LHS into the R3/R5-resident RHS using stack-bridged register moves
// because kunai owns only R3/R5 inside the where pipeline (R6-R8 are
// host-callee-saved, R0/R4 carry packet pointers we mustn't trample).
//
// Output: R3 = (lhs_high + rhs_high + carry) mod 2^64,
//
//	R5 = (lhs_low  + rhs_low)            mod 2^64
//
// (mirrored for sub: borrow propagates from low to high).
//
// The second operand runs while the first sits in slots 2/3, so it must
// not be an expression that parks there itself. When the right side is
// one (`a + (b + c)`), it goes first and the left side, which then must
// not park, second; for `-` the two are swapped back afterwards. Two
// parking sides (`(a + b) - (c + d)`) go to genArith128BothPark.
func (c *whereCtx) genArith128FieldOpField(e *ir.ArithExpr) (asm.Instructions, error) {
	if parks128(e.Left) && parks128(e.Right) {
		return c.genArith128BothPark(e)
	}
	first, second := e.Left, e.Right
	rightFirst := parks128(e.Right)
	if rightFirst {
		first, second = e.Right, e.Left
	}
	firstInsns, err := c.genArith128(first)
	if err != nil {
		return nil, err
	}
	secondInsns, err := c.genArith128(second)
	if err != nil {
		return nil, err
	}
	lhsHighSlot := arithStackSlot(2)
	lhsLowSlot := arithStackSlot(3)
	insns := append(asm.Instructions{}, firstInsns...)
	insns = append(insns,
		asm.StoreMem(asm.R10, lhsHighSlot, asm.R3, asm.DWord),
		asm.StoreMem(asm.R10, lhsLowSlot, asm.R5, asm.DWord),
	)
	insns = append(insns, secondInsns...)
	if rightFirst && e.Op == ast.ArithSub {
		// The slots hold the right operand and the registers the left;
		// `-` does not commute, so exchange them through R2.
		insns = append(insns,
			asm.LoadMem(asm.R2, asm.R10, lhsHighSlot, asm.DWord),
			asm.StoreMem(asm.R10, lhsHighSlot, asm.R3, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.LoadMem(asm.R2, asm.R10, lhsLowSlot, asm.DWord),
			asm.StoreMem(asm.R10, lhsLowSlot, asm.R5, asm.DWord),
			asm.Mov.Reg(asm.R5, asm.R2),
		)
	}
	// Slots = lhs, R3 = rhs_high, R5 = rhs_low. For a right-first `+`
	// the two names are exchanged, which the sum does not see.
	combine, err := c.genArith128Combine(e.Op)
	if err != nil {
		return nil, err
	}
	return append(insns, combine...), nil
}

// genArith128Combine adds or subtracts the 128-bit value in R3 (high) /
// R5 (low) into the one parked in arith slots 2 (high) / 3 (low), the
// left operand, and leaves the result in R3/R5.
func (c *whereCtx) genArith128Combine(op ast.ArithOp) (asm.Instructions, error) {
	lhsHighSlot := arithStackSlot(2)
	lhsLowSlot := arithStackSlot(3)
	var insns asm.Instructions
	switch op {
	case ast.ArithAdd:
		// Park rhs_high so we can recycle R3 as the "load lhs into a
		// register" slot. R5 keeps rhs_low until we add lhs_low.
		insns = append(insns, asm.StoreMem(asm.R10, arithStackSlot(4), asm.R3, asm.DWord))
		insns = append(insns, asm.LoadMem(asm.R3, asm.R10, lhsLowSlot, asm.DWord)) // R3 = lhs_low
		insns = append(insns, asm.Add.Reg(asm.R5, asm.R3))                         // R5 = lhs_low + rhs_low
		// Carry iff sum < lhs_low (R3 still holds lhs_low).
		noCarry := c.freshLabel("v128_ff_nocarry")
		insns = append(insns, asm.JGE.Reg(asm.R5, asm.R3, noCarry))
		insns = append(insns,
			asm.LoadMem(asm.R3, asm.R10, lhsHighSlot, asm.DWord),
			asm.Add.Imm(asm.R3, 1),
			asm.StoreMem(asm.R10, lhsHighSlot, asm.R3, asm.DWord),
		)
		insns = append(insns, landingNoop(noCarry))
		// R5 holds new_low. Compute R3 = rhs_high + lhs_high
		// (carry-adjusted). Park R5, free R3 for the high add.
		insns = append(insns,
			asm.StoreMem(asm.R10, lhsLowSlot, asm.R5, asm.DWord),       // park new_low briefly
			asm.LoadMem(asm.R3, asm.R10, arithStackSlot(4), asm.DWord), // R3 = rhs_high
			asm.LoadMem(asm.R5, asm.R10, lhsHighSlot, asm.DWord),       // R5 = lhs_high (carry-adjusted)
			asm.Add.Reg(asm.R3, asm.R5),                                // R3 = rhs_high + lhs_high
			asm.LoadMem(asm.R5, asm.R10, lhsLowSlot, asm.DWord),        // R5 = new_low restored
		)
	case ast.ArithSub:
		// Sub mirror: borrow ⇔ lhs_low < rhs_low. Detect first, then
		// subtract — the test reads the unwrapped lhs_low.
		insns = append(insns, asm.StoreMem(asm.R10, arithStackSlot(4), asm.R3, asm.DWord)) // park rhs_high
		insns = append(insns, asm.LoadMem(asm.R3, asm.R10, lhsLowSlot, asm.DWord))         // R3 = lhs_low
		noBorrow := c.freshLabel("v128_ff_noborrow")
		insns = append(insns, asm.JGE.Reg(asm.R3, asm.R5, noBorrow))
		insns = append(insns,
			asm.LoadMem(asm.R3, asm.R10, lhsHighSlot, asm.DWord),
			asm.Sub.Imm(asm.R3, 1),
			asm.StoreMem(asm.R10, lhsHighSlot, asm.R3, asm.DWord),
			asm.LoadMem(asm.R3, asm.R10, lhsLowSlot, asm.DWord), // R3 = lhs_low (restore for the sub below)
		)
		insns = append(insns, landingNoop(noBorrow))
		// R3 holds new_low after the subtract; park it directly so
		// the Mov R5,R3 + Store R5 → slot dance collapses to one
		// Store. R5 stays free for the rhs_high load below.
		insns = append(insns,
			asm.Sub.Reg(asm.R3, asm.R5),                                // R3 = lhs_low − rhs_low
			asm.StoreMem(asm.R10, lhsLowSlot, asm.R3, asm.DWord),       // park new_low
			asm.LoadMem(asm.R3, asm.R10, lhsHighSlot, asm.DWord),       // R3 = lhs_high (carry-adjusted)
			asm.LoadMem(asm.R5, asm.R10, arithStackSlot(4), asm.DWord), // R5 = rhs_high
			asm.Sub.Reg(asm.R3, asm.R5),                                // R3 = new_high
			asm.LoadMem(asm.R5, asm.R10, lhsLowSlot, asm.DWord),        // R5 = new_low
		)
	}
	return insns, nil
}

// genArithField128Load loads a 128-bit field into (R3=high, R5=low).
// The two LDX-DWord loads are followed by HostTo BE swaps so each
// half holds host-native ordering — the common shape for cmp and
// arith on IPv6 addresses (which the user reads as numeric ranges).
func (c *whereCtx) genArithField128Load(f *ir.FieldRef) (asm.Instructions, error) {
	if f == nil || f.Field == nil {
		return nil, fmt.Errorf("codegen: bit<128> field load with nil ref")
	}
	if f.Aux != nil {
		return nil, fmt.Errorf("%w: bit<128> arith on aux field is not yet wired", ErrNotImplemented)
	}
	if f.Field.Bits != 128 {
		return nil, fmt.Errorf("codegen: bit<128> path called with %d-bit field", f.Field.Bits)
	}
	anchor, err := c.layerAnchorFor(f.Layer)
	if err != nil {
		return nil, err
	}
	bitOff, _, err := findFieldByteOffset128(f.Layer.Spec, f.Field.Name)
	if err != nil {
		return nil, err
	}
	var insns asm.Instructions
	// High half load → R3, then bswap.
	insns = append(insns, emitFieldLoad(anchor, bitOff, asm.DWord)...)
	insns = append(insns, asm.HostTo(asm.BE, asm.R3, asm.DWord))
	// Stash high to a kunai-owned scratch slot (R6/R7/R8 belong to
	// the host per ABI doc — using them here would let the host's
	// pointers leak past the filter).
	insns = append(insns, asm.StoreMem(asm.R10, arithStackSlot(4), asm.R3, asm.DWord))
	insns = append(insns, emitFieldLoad(anchor, bitOff+8, asm.DWord)...)
	insns = append(insns, asm.HostTo(asm.BE, asm.R3, asm.DWord))
	// Move low to R5; reload the stashed high into R3.
	insns = append(insns, asm.Mov.Reg(asm.R5, asm.R3))
	insns = append(insns, asm.LoadMem(asm.R3, asm.R10, arithStackSlot(4), asm.DWord))
	return insns, nil
}

// genArithWithBits evaluates an arith expression into R3 (`depth` is the
// first arith slot it may use), with a target-width hint used to narrow
// integer-constant leaves at codegen time (dsl-types.md §5.2 / §7.3).
// targetBits = 0 means "no narrowing"; targetBits ∈ [1, 63] masks
// the constant to its low `targetBits` so 2's-complement negative
// literals fit the BPF int32 immediate.
func (c *whereCtx) genArithWithBits(e *ir.ArithExpr, depth int, targetBits int) (asm.Instructions, error) {
	// Cap the usable arith depth by the bool-eq LHS values currently
	// parked at the top of the arith region. genBoolEq parks one slot per
	// nesting level growing down from slot maxArithDepth-1, so operand
	// arith must stay strictly below the lowest parked slot; otherwise a
	// deep `+`/`-` chain inside a bool-eq operand reaches slot
	// (maxArithDepth-1) and overwrites the saved LHS, silently
	// mis-comparing. Outside any bool-eq (boolEqDepth == 0) the ceiling is
	// the full maxArithDepth, so non-bool-eq expressions are unaffected.
	ceiling := maxArithDepth - c.boolEqDepth
	if depth >= ceiling {
		return nil, fmt.Errorf("%w: arith expression nested deeper than %d levels", ErrNotImplemented, ceiling)
	}
	switch e.Kind {
	case ast.ArithConst:
		v := e.Const
		if targetBits > 0 && targetBits < 64 {
			v &= (uint64(1) << targetBits) - 1
		}
		return loadConst(asm.R3, v), nil
	case ast.ArithField:
		return c.genArithFieldLoad(e.Field)
	case ast.ArithBinOp:
		return c.genArithBinOp(e, depth)
	}
	return nil, fmt.Errorf("codegen: unknown arith kind %v", e.Kind)
}

// genArithFieldLoad reads a field from its absolute scratch position
// (R0 + layer_offset + field_offset) into R3. Multi-byte fields hit
// HostTo(BE) (BPF_END family, opcode 0xdc — works on Linux 5.x) to
// bring the register to natural integer order. BSwap (opcode 0xd7)
// would be one instruction shorter but only lands in 6.6+.
//
// For aux header fields the field offset already includes the aux
// header's OffsetInLayer, and any gating predicate must fire before
// the load. The gating check uses dslReject as the failure label
// because where-clause arith is sub-clauses inside a top-level
// where, and a missing aux means the where atom evaluates false —
// which the surrounding compound boolean handles via dslReject.
func (c *whereCtx) genArithFieldLoad(f *ir.FieldRef) (asm.Instructions, error) {
	if slot, ok := c.dynamicOffsetSlotFor(f); ok {
		return c.genDynamicOffsetAuxLoad(f, slot)
	}
	if needsEntryAddress(f) {
		// Dynamic stack index, or a static index into a stack of
		// variable-length entries: compute the entry's runtime offset off
		// the layer's where-context anchor, then byte-swap the loaded
		// value to natural order so downstream arithmetic / comparison
		// sees the network-order integer; a bit slice narrows it after.
		anchor, err := c.layerAnchorFor(f.Layer)
		if err != nil {
			return nil, err
		}
		fieldByteOff, fieldBytes, err := auxEntryFieldWindow(f)
		if err != nil {
			return nil, err
		}
		size, err := asmSizeFor(fieldBytes)
		if err != nil {
			return nil, err
		}
		addr, err := c.stackEntryAddress(f, anchor, c.absent())
		if err != nil {
			return nil, err
		}
		insns := append(addr, asm.LoadMem(asm.R3, asm.R5, int16(fieldByteOff), size))
		if fieldBytes > 1 {
			insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
		}
		insns = append(insns, emitSliceShiftMask(f, fieldBytes)...)
		return insns, nil
	}
	anchor, err := c.layerAnchorFor(f.Layer)
	if err != nil {
		return nil, err
	}
	fieldOff, fieldBytes, err := fieldRefByteOffset(f)
	if err != nil {
		return nil, err
	}
	size, err := asmSizeFor(fieldBytes)
	if err != nil {
		return nil, err
	}
	var insns asm.Instructions
	if f.Aux != nil {
		insns = append(insns, emitAuxGating(f.Aux.Gating, anchor, c.absent())...)
	}
	insns = append(insns, emitFieldLoad(anchor, fieldOff, size)...)
	if fieldBytes > 1 {
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	insns = append(insns, emitSliceShiftMask(f, fieldBytes)...)
	return insns, nil
}

// emitSliceShiftMask returns the post-load shift + AND instructions
// that narrow R3 down to the slice's actual bits when the slice is
// non-byte-aligned (or otherwise smaller than the load). Returns
// empty when no adjustment is needed.
func emitSliceShiftMask(f *ir.FieldRef, loadBytes int) asm.Instructions {
	shift, mask := slicePostAdjust(f, loadBytes)
	if shift == 0 && mask == 0 {
		return nil
	}
	var insns asm.Instructions
	if shift > 0 {
		insns = append(insns, asm.RSh.Imm(asm.R3, int32(shift)))
	}
	if mask != 0 && mask != ^uint64(0) {
		if mask <= math.MaxInt32 {
			insns = append(insns, asm.And.Imm(asm.R3, int32(mask)))
		} else {
			insns = append(insns, loadConst(asm.R5, mask)...)
			insns = append(insns, asm.And.Reg(asm.R3, asm.R5))
		}
	}
	return insns
}

// genArithBinOp evaluates left, saves R3 to a depth-indexed stack
// slot, evaluates right, reloads left to R5, and applies the op so
// R5 ⬅ R5 op R3; the result is then moved back into R3 for the
// caller.
func (c *whereCtx) genArithBinOp(e *ir.ArithExpr, depth int) (asm.Instructions, error) {
	// A literal operand is narrowed to the width of the operand next to
	// it (§7.3, D-009): `tcp.dport + -1` adds 0xffff, not a 64-bit -1.
	// With no field on the other side it stays a 64-bit value.
	left, err := c.genArithWithBits(e.Left, depth+1, arithMaxFieldBits(e.Right))
	if err != nil {
		return nil, err
	}
	right, err := c.genArithWithBits(e.Right, depth+1, arithMaxFieldBits(e.Left))
	if err != nil {
		return nil, err
	}
	aluOp, err := arithALUOp(e.Op)
	if err != nil {
		return nil, err
	}
	slot := arithStackSlot(depth)
	var insns asm.Instructions
	insns = append(insns, left...)
	insns = append(insns, asm.StoreMem(asm.R10, slot, asm.R3, asm.DWord))
	insns = append(insns, right...)
	insns = append(insns, asm.LoadMem(asm.R5, asm.R10, slot, asm.DWord))
	insns = append(insns, aluOp.Reg(asm.R5, asm.R3))
	insns = append(insns, asm.Mov.Reg(asm.R3, asm.R5))
	return insns, nil
}

func arithStackSlot(depth int) int16 {
	return int16(arithStackBase - depth*8)
}

func arithALUOp(op ast.ArithOp) (asm.ALUOp, error) {
	switch op {
	case ast.ArithAdd:
		return asm.Add, nil
	case ast.ArithSub:
		return asm.Sub, nil
	case ast.ArithMul:
		return asm.Mul, nil
	case ast.ArithDiv:
		return asm.Div, nil
	case ast.ArithMod:
		return asm.Mod, nil
	case ast.ArithAnd:
		return asm.And, nil
	case ast.ArithOr:
		return asm.Or, nil
	case ast.ArithXor:
		return asm.Xor, nil
	case ast.ArithShl:
		return asm.LSh, nil
	case ast.ArithShr:
		return asm.RSh, nil
	}
	return 0, fmt.Errorf("codegen: unknown arith op %v", op)
}

// layerAbsoluteOffset returns the scratch-buffer byte offset at which
// target's header begins.
func layerAbsoluteOffset(target *ir.LayerInstance, p *ir.Program) (int, error) {
	return prefixHeaderSize(p, target, "where-clause field", uniformAltPrefixSize, exactInstances)
}

// prefixHeaderSize sums header sizes of p.Layers up to (but not
// including) until. If until is nil every layer is summed. Any
// quantified layer in the traversed range — including until itself —
// fails with ErrNotImplemented, because the prefix length would
// otherwise be runtime-variable. reason is surfaced verbatim in the
// error message ("where-clause field", "capture headers", ...).
//
// altReducer decides how to score an alt group within the prefix:
//
//   - uniformAltPrefixSize: requires every member to agree on size;
//     used by where, where R0-static field offsets cannot tolerate a
//     runtime-variable prefix (the slot path takes over for marked
//     layers; this stays the fallback that errors loudly).
//   - maxAltPrefixSize: returns the largest member's size; used by
//     capture, which over-captures by a few bytes when the smaller
//     alt fired rather than refusing the chain.
func prefixHeaderSize(p *ir.Program, until *ir.LayerInstance, reason string, altReducer func([]*ir.LayerInstance, string) (int, error), instances func(*ir.LayerInstance, string) (int, error)) (int, error) {
	total := 0
	for _, l := range p.Layers {
		// An alternation member as the target: the prefix stops before
		// its group (every member starts there).
		if l == until || slices.Contains(l.Alternation, until) {
			if l == until {
				if _, err := instances(l, reason+" on"); err != nil {
					return 0, err
				}
			}
			return total, nil
		}
		n, err := instances(l, reason+" past")
		if err != nil {
			return 0, err
		}
		var hs int
		if l.Alternation != nil {
			hs, err = altReducer(l.Alternation, reason)
		} else {
			hs, err = headerSize(l.Spec)
		}
		if err != nil {
			return 0, err
		}
		total += n * hs
	}
	if until != nil {
		return 0, fmt.Errorf("codegen: %s references layer %q which is not in program", reason, layerName(until))
	}
	return total, nil
}

// exactInstances is the where-side quantifier policy: a static prefix
// needs every layer to match exactly one header. `what` is the reason
// plus "on" / "past" for the diagnostic.
func exactInstances(l *ir.LayerInstance, what string) (int, error) {
	if l.Quant != ast.QuantOne {
		return 0, fmt.Errorf("%w: %s quantified layer %q", ErrNotImplemented, what, l.Spec.Name)
	}
	return 1, nil
}

// upperInstances is the capture-side policy: every instance a
// quantifier allows counts (layerMaxInstances).
func upperInstances(l *ir.LayerInstance, _ string) (int, error) {
	return layerMaxInstances(l)
}

// prefixHeaderSizeMaxAlt is the capture-side wrapper that rounds
// heterogeneous alts up to their largest member instead of erroring.
func prefixHeaderSizeMaxAlt(p *ir.Program, until *ir.LayerInstance, reason string) (int, error) {
	return prefixHeaderSize(p, until, reason, maxAltPrefixSize, exactInstances)
}

// prefixHeaderSizeUpper bounds the bytes the layers before `until` (all
// of them when nil) can span: the largest alternation member and every
// instance a quantifier allows (layerMaxInstances) count. Capture lengths
// use it; where-clause addressing keeps prefixHeaderSize, whose static
// prefix must be exact.
func prefixHeaderSizeUpper(p *ir.Program, until *ir.LayerInstance, reason string) (int, error) {
	return prefixHeaderSize(p, until, reason, maxAltPrefixSize, upperInstances)
}

// layerMaxInstances is the most headers a layer can match: one for a
// plain or `?` layer, the quantifier's upper bound otherwise, with the
// chain's iteration cap standing in for an open bound.
func layerMaxInstances(l *ir.LayerInstance) (int, error) {
	switch l.Quant {
	case ast.QuantRange:
		if l.RangeMax >= 0 {
			return l.RangeMax, nil
		}
		return chainMaxIter(l)
	case ast.QuantPlus, ast.QuantStar:
		return chainMaxIter(l)
	}
	return 1, nil
}

// uniformAltPrefixSize is the strict altReducer: every alt must agree
// on size, otherwise ErrNotImplemented. Used by where, paired with
// the slot-anchor path (resolver marks layers past a het-alt to use
// the slot, so this only errors when the resolver missed the mark).
func uniformAltPrefixSize(alts []*ir.LayerInstance, reason string) (int, error) {
	min, max, err := altPrefixSizeRange(alts)
	if err != nil {
		return 0, err
	}
	if min != max {
		return 0, fmt.Errorf("%w: %s past heterogeneous-size alternation group (alts differ in primary header size — would need R4-relative addressing)", ErrNotImplemented, reason)
	}
	return max, nil
}

// maxAltPrefixSize is the lenient altReducer: returns the largest
// member's size, ignoring disagreement. Used by capture to upper-
// bound the static capture length.
func maxAltPrefixSize(alts []*ir.LayerInstance, _ string) (int, error) {
	_, max, err := altPrefixSizeRange(alts)
	return max, err
}

// altPrefixSizeRange returns the smallest and largest member header
// sizes; the two altReducer variants pick from there.
func altPrefixSizeRange(alts []*ir.LayerInstance) (min, max int, err error) {
	first := true
	for _, alt := range alts {
		hs, herr := headerSize(alt.Spec)
		if herr != nil {
			return 0, 0, herr
		}
		if first {
			min, max = hs, hs
			first = false
			continue
		}
		if hs < min {
			min = hs
		}
		if hs > max {
			max = hs
		}
	}
	return min, max, nil
}

// genActionAtom emits the load+compare for `where action == NAME`.
// The host capability supplies (a) the integer the symbolic NAME
// compares against and (b) instructions that materialise the action
// u32 in R3. When caps disable action atoms (Action map nil or
// fetcher nil) this returns ErrNotImplemented — the resolver
// normally catches that earlier with a clearer message.
func genActionAtom(w *ir.Condition, lang LangCaps, failLabel string) (asm.Instructions, error) {
	if !lang.HasActionAtoms() {
		return nil, fmt.Errorf("%w: `action == %s` is not available on this host (action atoms require both LangCaps.Action and LangCaps.ActionFetcher to be set)", ErrNotImplemented, w.ActionValue)
	}
	val, ok := lang.Action[w.ActionValue]
	if !ok {
		return nil, fmt.Errorf("codegen: unknown action %q (host LangCaps.Action has %d entries)", w.ActionValue, len(lang.Action))
	}
	insns := lang.ActionFetcher.EmitFetch(asm.R3)
	// 32-bit JNE so signed action values (e.g. TC_ACT_UNSPEC = -1)
	// compare against R3's low 32 bits without 64-bit sign-extension
	// of the immediate. R3 is loaded zero-extended via Word LDX, so
	// a 64-bit JNE.Imm against -1 sign-extends the imm to 0xFFFF_FFFF_FFFF_FFFF
	// and never matches R3's 0x0000_0000_FFFF_FFFF — silently always rejects.
	return append(insns, asm.JNE.Imm32(asm.R3, val, failLabel)), nil
}

// genLiteralCompare emits `field <op> <network literal>` for where
// clauses. The shape mirrors emitIPv4Predicate / emitIPv6Predicate /
// emitMACPredicate / emitIPv4CIDRPredicate / emitIPv6CIDRPredicate
// from predicate.go but reads from an absolute scratch offset
// (`R0 + layer_entry + field_offset`) instead of the R4-relative
// position predicates use. The constant is byte-swapped at codegen
// time so a single JEq / JNE matches the LE-loaded register without
// emitting a runtime swap (same reasoning as emitIntPredicate).
//
// For aux refs:
//   - Single auxes and static stack indices fold into a fixed
//     `base` offset; gating fires before the load when present.
//   - Runtime-offset entries (dynamic index, variable-length entries)
//     route through emitStackEntryAddress,
//     which leaves R5 = element start so subsequent LDX use
//     R5-relative offsets instead of R0-relative.
func (c *whereCtx) genLiteralCompare(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w == nil || w.LiteralField == nil || w.LiteralField.Layer == nil {
		return nil, fmt.Errorf("codegen: WAtomLiteralCmp condition missing field reference")
	}
	ref := w.LiteralField
	jumpOp, ok := ipEqualityJumpOp(w.LiteralOp)
	if !ok {
		return nil, fmt.Errorf("%w: network literal supports only == / != (got %s)", ErrNotImplemented, w.LiteralOp)
	}
	if ref.Aux != nil && ref.Aux.OwnerOption != nil {
		return c.genOwnerBoundLiteralCompare(w, failLabel)
	}
	if needsEntryAddress(ref) {
		return c.genLiteralCompareDynamic(w, failLabel)
	}
	anchor, err := c.layerAnchorFor(ref.Layer)
	if err != nil {
		return nil, err
	}
	fieldOff, fieldBytes, err := whereLiteralFieldOffset(ref)
	if err != nil {
		return nil, err
	}

	var prelude asm.Instructions
	if ref.Aux != nil {
		prelude = emitAuxGating(ref.Aux.Gating, anchor, failLabel)
	}

	switch w.LiteralValue.Kind {
	case ast.ValIPv4:
		if fieldBytes != 4 {
			return nil, fmt.Errorf("%w: IPv4 literal needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		v4 := w.LiteralValue.V4
		expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, emitFieldLoad(anchor, fieldOff, asm.Word)...)
		insns = append(insns, cmpRegEqU32(jumpOp, expected, failLabel)...)
		return insns, nil

	case ast.ValMAC:
		if fieldBytes != 6 {
			return nil, fmt.Errorf("%w: MAC literal needs a 6-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		mac := w.LiteralValue.MAC
		highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
		lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))
		return append(prelude, whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			insns := emitFieldLoad(anchor, fieldOff, asm.Word)
			insns = append(insns, cmpRegEqU32(asm.JNE, highLE, fail)...)
			insns = append(insns, emitFieldLoad(anchor, fieldOff+4, asm.Half)...)
			insns = append(insns, cmpRegEqU16(asm.JNE, lowLE, fail)...)
			return insns
		})...), nil

	case ast.ValIPv6:
		if fieldBytes != 16 {
			return nil, fmt.Errorf("%w: IPv6 literal needs a 16-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		highBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8])
		lowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16])
		return append(prelude, whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			return append(
				whereIPv6HalfCheck(anchor, fieldOff, ^uint64(0), highBE, fail),
				whereIPv6HalfCheck(anchor, fieldOff+8, ^uint64(0), lowBE, fail)...,
			)
		})...), nil

	case ast.ValCIDR:
		if w.LiteralValue.AF == 4 {
			return c.genIPv4CIDRCompare(w, anchor, fieldOff, fieldBytes, failLabel, jumpOp)
		}
		return c.genIPv6CIDRCompare(w, anchor, fieldOff, fieldBytes, failLabel)
	}
	return nil, fmt.Errorf("%w: where literal kind %v", ErrNotImplemented, w.LiteralValue.Kind)
}

// whereLiteralFieldOffset returns the byte offset (relative to the
// layer's start) and byte width of the LiteralField — primary or
// aux. For static stack indices the index*ElemSize is folded in;
// dynamic indices return ErrNotImplemented from this helper because
// they need runtime offset emit (see genLiteralCompareDynamic).
func whereLiteralFieldOffset(ref *ir.FieldRef) (int, int, error) {
	if ref.Aux == nil {
		bitOff, bits, err := findFieldBitOffset(ref.Layer.Spec, ref.Field.Name)
		if err != nil {
			return 0, 0, err
		}
		if bitOff%8 != 0 || bits%8 != 0 {
			return 0, 0, fmt.Errorf("%w: %s.%s is not byte-aligned (bit offset %d, %d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Field.Name, bitOff, bits)
		}
		return bitOff / 8, bits / 8, nil
	}
	aux := ref.Aux
	if aux.FieldBitOff%8 != 0 || aux.FieldBitWidth%8 != 0 {
		return 0, 0, fmt.Errorf("%w: aux field %s.%s.%s not byte-aligned", ErrNotImplemented, ref.Layer.Spec.Name, aux.OutParam, ref.Field.Name)
	}
	off := aux.OffsetInLayer + aux.FieldBitOff/8
	if aux.Stack != nil {
		if !aux.Stack.IsStatic {
			return 0, 0, fmt.Errorf("%w: dynamic stack index requires runtime offset emit", ErrNotImplemented)
		}
		off += int(aux.Stack.Static) * aux.HeaderSize
	}
	return off, aux.FieldBitWidth / 8, nil
}

// genLiteralCompareDynamic emits the dynamic-stack-index path for
// network-literal comparisons. The address compute lands in R5; the
// per-kind body issues 1..N LDX from R5 + (FieldBitOff/8 + delta)
// and compares each load against a byte-swapped constant. Gating
// does not apply: stack auxes are extracted unconditionally inside
// the parser-machine self-loop.
func (c *whereCtx) genLiteralCompareDynamic(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	ref := w.LiteralField
	off, fieldBytes, err := auxEntryFieldWindow(ref)
	if err != nil {
		return nil, err
	}
	fieldByteOff := int16(off)

	switch w.LiteralValue.Kind {
	case ast.ValIPv4:
		if fieldBytes != 4 {
			return nil, fmt.Errorf("%w: IPv4 literal needs a 4-byte field, got %d-byte %s.%s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name)
		}
		v4 := w.LiteralValue.V4
		expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
		jumpOp, _ := ipEqualityJumpOp(w.LiteralOp)
		return whereDynamicMultiByte(c, ref, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			return append(asm.Instructions{
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff, asm.Word),
			}, cmpRegEqU32(jumpOp, expected, fail)...)
		})

	case ast.ValIPv6:
		if fieldBytes != 16 {
			return nil, fmt.Errorf("%w: IPv6 literal needs a 16-byte field, got %d-byte %s.%s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name)
		}
		highBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8])
		lowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16])
		// R5 is occupied (= dynamic stack element address base). R6
		// is callee-saved and holds xdp_buff in the runtime prelude
		// — clobbering it breaks downstream helper calls. R2 is
		// caller-saved scratch and free at this point.
		return whereDynamicMultiByte(c, ref, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			insns := asm.Instructions{
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff, asm.DWord),
				asm.LoadImm(asm.R2, int64(byteSwap(highBE, 8)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff+8, asm.DWord),
				asm.LoadImm(asm.R2, int64(byteSwap(lowBE, 8)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			}
			return insns
		})

	case ast.ValMAC:
		if fieldBytes != 6 {
			return nil, fmt.Errorf("%w: MAC literal needs a 6-byte field, got %d-byte %s.%s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name)
		}
		mac := w.LiteralValue.MAC
		highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
		lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))
		return whereDynamicMultiByte(c, ref, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			return asm.Instructions{
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff, asm.Word),
				asm.LoadImm(asm.R2, int64(uint64(highLE)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff+4, asm.Half),
				asm.LoadImm(asm.R2, int64(uint64(lowLE)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			}
		})

	case ast.ValCIDR:
		if w.LiteralValue.AF == 4 {
			return c.genDynamicCIDRv4(w, ref, fieldByteOff, fieldBytes, failLabel)
		}
		return c.genDynamicCIDRv6(w, ref, fieldByteOff, fieldBytes, failLabel)
	}
	return nil, fmt.Errorf("%w: dynamic-index aux compare for literal kind %v", ErrNotImplemented, w.LiteralValue.Kind)
}

func (c *whereCtx) genDynamicCIDRv4(w *ir.Condition, ref *ir.FieldRef, fieldByteOff int16, fieldBytes int, failLabel string) (asm.Instructions, error) {
	if fieldBytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 CIDR needs a 4-byte field, got %d-byte %s.%s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 32 {
		return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", prefix)
	}
	jumpOp, _ := ipEqualityJumpOp(w.LiteralOp)
	if prefix == 0 {
		if w.LiteralOp == ast.CmpEq {
			return nil, nil
		}
		return asm.Instructions{asm.Ja.Label(failLabel)}, nil
	}
	maskBE := uint32(0xFFFFFFFF) << (32 - prefix)
	hostBE := binary.BigEndian.Uint32(w.LiteralValue.V4[:]) & maskBE
	maskLE := uint32(byteSwap(uint64(maskBE), 4))
	hostLE := uint32(byteSwap(uint64(hostBE), 4))
	if prefix == 32 {
		return whereDynamicMultiByte(c, ref, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			return append(asm.Instructions{
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff, asm.Word),
			}, cmpRegEqU32(jumpOp, hostLE, fail)...)
		})
	}
	return whereDynamicMultiByte(c, ref, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
		insns := asm.Instructions{
			asm.LoadMem(asm.R3, asm.R5, fieldByteOff, asm.Word),
			asm.And.Imm(asm.R3, int32(maskLE)),
		}
		insns = append(insns, cmpRegEqU32(asm.JNE, hostLE, fail)...)
		return insns
	})
}

func (c *whereCtx) genDynamicCIDRv6(w *ir.Condition, ref *ir.FieldRef, fieldByteOff int16, fieldBytes int, failLabel string) (asm.Instructions, error) {
	if fieldBytes != 16 {
		return nil, fmt.Errorf("%w: IPv6 CIDR needs a 16-byte field, got %d-byte %s.%s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 128 {
		return nil, fmt.Errorf("codegen: IPv6 CIDR prefix %d out of [0,128]", prefix)
	}
	if prefix == 0 {
		if w.LiteralOp == ast.CmpEq {
			return nil, nil
		}
		return asm.Instructions{asm.Ja.Label(failLabel)}, nil
	}
	maskHighBE, maskLowBE := ipv6PrefixMaskBE(prefix)
	hostHighBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8]) & maskHighBE
	hostLowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16]) & maskLowBE
	return whereDynamicMultiByte(c, ref, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
		var insns asm.Instructions
		if maskHighBE != 0 {
			insns = append(insns,
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff, asm.DWord),
			)
			if maskHighBE != ^uint64(0) {
				insns = append(insns,
					asm.LoadImm(asm.R2, int64(byteSwap(maskHighBE, 8)), asm.DWord),
					asm.And.Reg(asm.R3, asm.R2),
				)
			}
			insns = append(insns,
				asm.LoadImm(asm.R2, int64(byteSwap(hostHighBE, 8)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
		}
		if maskLowBE != 0 {
			insns = append(insns,
				asm.LoadMem(asm.R3, asm.R5, fieldByteOff+8, asm.DWord),
			)
			if maskLowBE != ^uint64(0) {
				insns = append(insns,
					asm.LoadImm(asm.R2, int64(byteSwap(maskLowBE, 8)), asm.DWord),
					asm.And.Reg(asm.R3, asm.R2),
				)
			}
			insns = append(insns,
				asm.LoadImm(asm.R2, int64(byteSwap(hostLowBE, 8)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
		}
		return insns
	})
}

// genOwnerBoundLiteralCompare emits a literal compare against an
// owner-bound static-stack aux field (B-4 SACK / future RR). The
// auxLoadEmitter prelude loads the owner option's per-packet base
// from its dynamic-aux slot, sentinel-checks (option absent → fail),
// and lands R5 = R0 + slot + (OffsetAfterOwner + Static*ElemSize).
// Per-kind body issues R5-relative LDX at FieldByteOff + chunkOff
// for each word in the literal.
func (c *whereCtx) genOwnerBoundLiteralCompare(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	ref := w.LiteralField
	jumpOp, _ := ipEqualityJumpOp(w.LiteralOp)
	anchor, err := c.layerAnchorFor(ref.Layer)
	if err != nil {
		return nil, err
	}
	prelude, loadAt, err := auxLoadEmitter(ref, anchor, c.dynamicOffsetSlotFor, failLabel)
	if err != nil {
		return nil, err
	}

	switch w.LiteralValue.Kind {
	case ast.ValIPv4:
		if ref.Aux.FieldBitWidth != 32 {
			return nil, fmt.Errorf("%w: IPv4 literal needs a 32-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth)
		}
		v4 := w.LiteralValue.V4
		expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, loadAt(0, asm.Word)...)
		insns = append(insns, cmpRegEqU32(jumpOp, expected, failLabel)...)
		return insns, nil

	case ast.ValIPv6:
		if ref.Aux.FieldBitWidth != 128 {
			return nil, fmt.Errorf("%w: IPv6 literal needs a 128-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth)
		}
		highBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8])
		lowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16])
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			body := loadAt(0, asm.DWord)
			body = append(body,
				asm.LoadImm(asm.R2, int64(byteSwap(highBE, 8)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
			body = append(body, loadAt(8, asm.DWord)...)
			body = append(body,
				asm.LoadImm(asm.R2, int64(byteSwap(lowBE, 8)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
			return body
		})...)
		return insns, nil

	case ast.ValMAC:
		if ref.Aux.FieldBitWidth != 48 {
			return nil, fmt.Errorf("%w: MAC literal needs a 48-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth)
		}
		mac := w.LiteralValue.MAC
		highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
		lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			body := loadAt(0, asm.Word)
			body = append(body,
				asm.LoadImm(asm.R2, int64(uint64(highLE)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
			body = append(body, loadAt(4, asm.Half)...)
			body = append(body,
				asm.LoadImm(asm.R2, int64(uint64(lowLE)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
			return body
		})...)
		return insns, nil

	case ast.ValCIDR:
		if w.LiteralValue.AF == 4 {
			return c.genOwnerBoundCIDRv4(w, prelude, loadAt, failLabel, jumpOp)
		}
		return c.genOwnerBoundCIDRv6(w, prelude, loadAt, failLabel)
	}
	return nil, fmt.Errorf("%w: owner-bound aux compare for literal kind %v", ErrNotImplemented, w.LiteralValue.Kind)
}

func (c *whereCtx) genOwnerBoundCIDRv4(w *ir.Condition, prelude asm.Instructions, loadAt auxLoadAt, failLabel string, jumpOp asm.JumpOp) (asm.Instructions, error) {
	ref := w.LiteralField
	if ref.Aux.FieldBitWidth != 32 {
		return nil, fmt.Errorf("%w: IPv4 CIDR needs a 32-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 32 {
		return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", prefix)
	}
	if prefix == 0 {
		if w.LiteralOp == ast.CmpEq {
			return prelude, nil
		}
		return append(prelude, asm.Ja.Label(failLabel)), nil
	}
	maskBE := uint32(0xFFFFFFFF) << (32 - prefix)
	hostBE := binary.BigEndian.Uint32(w.LiteralValue.V4[:]) & maskBE
	maskLE := uint32(byteSwap(uint64(maskBE), 4))
	hostLE := uint32(byteSwap(uint64(hostBE), 4))
	insns := append(asm.Instructions{}, prelude...)
	if prefix == 32 {
		insns = append(insns, loadAt(0, asm.Word)...)
		insns = append(insns, cmpRegEqU32(jumpOp, hostLE, failLabel)...)
		return insns, nil
	}
	insns = append(insns, whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
		body := loadAt(0, asm.Word)
		body = append(body, asm.And.Imm(asm.R3, int32(maskLE)))
		body = append(body, cmpRegEqU32(asm.JNE, hostLE, fail)...)
		return body
	})...)
	return insns, nil
}

func (c *whereCtx) genOwnerBoundCIDRv6(w *ir.Condition, prelude asm.Instructions, loadAt auxLoadAt, failLabel string) (asm.Instructions, error) {
	ref := w.LiteralField
	if ref.Aux.FieldBitWidth != 128 {
		return nil, fmt.Errorf("%w: IPv6 CIDR needs a 128-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 128 {
		return nil, fmt.Errorf("codegen: IPv6 CIDR prefix %d out of [0,128]", prefix)
	}
	if prefix == 0 {
		if w.LiteralOp == ast.CmpEq {
			return prelude, nil
		}
		return append(prelude, asm.Ja.Label(failLabel)), nil
	}
	maskHighBE, maskLowBE := ipv6PrefixMaskBE(prefix)
	hostHighBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8]) & maskHighBE
	hostLowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16]) & maskLowBE
	insns := append(asm.Instructions{}, prelude...)
	insns = append(insns, whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
		var body asm.Instructions
		if maskHighBE != 0 {
			body = append(body, ipv6AuxHalfCheck(loadAt, 0, maskHighBE, hostHighBE, fail)...)
		}
		if maskLowBE != 0 {
			body = append(body, ipv6AuxHalfCheck(loadAt, 8, maskLowBE, hostLowBE, fail)...)
		}
		return body
	})...)
	return insns, nil
}

// dynamicOffsetSlotFor reports the stack slot a FieldRef should
// read its aux offset from — non-zero only when the demand walker
// claimed this aux during compile (the slot the parser-machine
// callback wrote the per-packet offset to). Callers fall through
// to other where paths when the aux isn't dynamic-eligible.
func (c *whereCtx) dynamicOffsetSlotFor(f *ir.FieldRef) (int16, bool) {
	layout := dynamicAuxLayoutOf(f)
	if layout == nil {
		return 0, false
	}
	return c.queried.dynamicAuxSlotForLayout(f.Layer, layout)
}

// stackEntryAddress is the where-side emitStackEntryAddress: a dynamic
// index into a push-counted stack is also bounded by the push count slot
// (D-031).
func (c *whereCtx) stackEntryAddress(ref *ir.FieldRef, base layerAnchor, failLabel string) (asm.Instructions, error) {
	var countSlot *int16
	if !ref.Aux.Stack.IsStatic && needsPushCount(ref) {
		slot, ok := c.queried.stackCountSlot(ref.Layer, ref.Aux.OutParam)
		if !ok {
			return nil, fmt.Errorf("codegen: push count of stack %q not in demand set", ref.Aux.OutParam)
		}
		countSlot = &slot
	}
	return emitStackEntryAddress(ref, base, countSlot, failLabel)
}

// absent is the jump target for a field whose option, gated aux, or
// stack entry is not present on this packet: the enclosing atom's fail
// label (the atom is false, D-027), or dslReject when no atom is open.
func (c *whereCtx) absent() string {
	if c.atomFail != "" {
		return c.atomFail
	}
	return dslReject
}

// genDynamicOffsetAuxLoad reads an aux header field whose layer
// position was recorded by the parser machine into a dynamic offset
// slot. The slot value is the absolute scratch offset of the aux's
// first byte; sentinel (-1) means the option was not extracted on
// this packet — the predicate evaluates false (jumps to dslReject).
//
// Two addressing modes folded into the same byteOff:
//   - Single aux: byteOff = FieldBitOff/8.
//   - Owner-bound stack: byteOff = OffsetAfterOwner +
//     Static*ElemSize + FieldBitOff/8. The slot still holds the
//     OWNER option's base; the element offset is folded here at
//     codegen time. Iterator indices are rebound to a static index
//     by the surrounding any/all unroll before reaching this site.
func (c *whereCtx) genDynamicOffsetAuxLoad(f *ir.FieldRef, slot int16) (asm.Instructions, error) {
	if f.Aux.FieldBitOff%8 != 0 || f.Aux.FieldBitWidth%8 != 0 {
		return nil, fmt.Errorf("%w: dynamic-offset aux field %s.%s not byte-aligned (bit-off %d, %d bits)", ErrNotImplemented, f.Layer.Spec.Name, f.Aux.OutParam, f.Aux.FieldBitOff, f.Aux.FieldBitWidth)
	}
	byteOff := f.Aux.FieldBitOff / 8
	if f.Aux.OwnerOption != nil {
		stack := f.Aux.Stack
		if stack == nil {
			return nil, fmt.Errorf("%w: owner-bound aux %q has no stack index — predicate codegen needs Static/Dynamic/Iterator", ErrNotImplemented, f.Aux.OutParam)
		}
		if !stack.IsStatic {
			return nil, fmt.Errorf("%w: owner-bound aux %q with non-static index is not yet supported", ErrNotImplemented, f.Aux.OutParam)
		}
		byteOff += f.Aux.OffsetAfterOwner + int(stack.Static)*f.Aux.HeaderSize
	}
	fieldBytes := f.Aux.FieldBitWidth / 8
	size, err := asmSizeFor(fieldBytes)
	if err != nil {
		return nil, err
	}
	insns := emitDynamicAuxByteLoad(slot, byteOff, size, c.absent())
	if fieldBytes > 1 {
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	return insns, nil
}

// emitDynamicAuxByteLoad emits the canonical "load a byte at
// `slot[OwnerOption] + byteOff`" sequence used by every dynamic-aux
// where-time access:
//
//   - LoadMem R3 ← slot value (= aux's per-packet base in scratch)
//   - JEq sentinel: option absent on this packet, jump to failLabel
//   - foldOffsetIntoScalar R5 = R3 + byteOff (scalar narrowed for
//     verifier precision)
//   - boundedScalarLoad R3 = *(scratch[R5]) at the requested size
//
// On return R3 holds the loaded value (host endianness — caller is
// responsible for HostTo if a multi-byte field needs byte-swap). R0/
// R1/R5 are clobbered.
func emitDynamicAuxByteLoad(slot int16, byteOff int, size asm.Size, failLabel string) asm.Instructions {
	insns := asm.Instructions{
		asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
		asm.JEq.Imm(asm.R3, dynamicAuxSentinel, failLabel),
	}
	insns = append(insns, foldOffsetIntoScalar(asm.R5, asm.R3, int32(byteOff), failLabel)...)
	insns = append(insns, boundedScalarLoad(asm.R3, asm.R0, asm.R5, asm.R1, size, failLabel)...)
	return insns
}

// whereDynamicMultiByte emits the address compute (R5 = element
// start) once, then runs the per-kind body whose instructions
// already use R5-relative LDX. multiWordRoute is honoured so `!=`
// branches through a per-clause match landing while `==` jumps to
// failLabel directly on any mismatch.
func whereDynamicMultiByte(c *whereCtx, ref *ir.FieldRef, op ast.CmpOp, failLabel string, body func(fail string) asm.Instructions) (asm.Instructions, error) {
	// layerAnchorFor (not the static-only layerOffset) so a dynamic aux
	// index resolves correctly when its layer sits past a runtime-offset
	// boundary (e.g. srv6 segments after ipv6 ext headers, or any stack
	// past a variable-length predecessor). emitStackEntryAddress
	// already handles slot anchors.
	anchor, err := c.layerAnchorFor(ref.Layer)
	if err != nil {
		return nil, err
	}
	if op == ast.CmpEq {
		addr, err := c.stackEntryAddress(ref, anchor, failLabel)
		if err != nil {
			return nil, err
		}
		return append(addr, body(failLabel)...), nil
	}
	// An entry that is not there makes the atom false for `!=` too (D-031).
	match := c.freshLabel("where_lit_match")
	addr, err := c.stackEntryAddress(ref, anchor, failLabel)
	if err != nil {
		return nil, err
	}
	out := append(addr, body(match)...)
	return append(out, asm.Ja.Label(failLabel), landingNoop(match)), nil
}

// whereMultiWordRoute is the where-side analogue of multiWordRoute
// in predicate.go: shapes the body around `==` (any mismatch jumps
// to failLabel) vs `!=` (mismatch hits a per-clause match landing,
// fall-through goes to failLabel).
func whereMultiWordRoute(c *whereCtx, op ast.CmpOp, failLabel string, body func(fail string) asm.Instructions) asm.Instructions {
	if op == ast.CmpEq {
		return body(failLabel)
	}
	match := c.freshLabel("where_lit_match")
	out := body(match)
	return append(out, asm.Ja.Label(failLabel), landingNoop(match))
}

// whereIPv6HalfCheck emits the load + optional AND + JNE for one
// 8-byte half of an IPv6 host or CIDR check at an absolute scratch
// offset. Mirror of ipv6HalfCheck in predicate.go.
func whereIPv6HalfCheck(anchor layerAnchor, fieldOff int, mask, host uint64, failLabel string) asm.Instructions {
	insns := emitFieldLoad(anchor, fieldOff, asm.DWord)
	if mask != ^uint64(0) {
		insns = append(insns,
			asm.LoadImm(asm.R5, int64(byteSwap(mask, 8)), asm.DWord),
			asm.And.Reg(asm.R3, asm.R5),
		)
	}
	insns = append(insns,
		asm.LoadImm(asm.R5, int64(byteSwap(host, 8)), asm.DWord),
		asm.JNE.Reg(asm.R3, asm.R5, failLabel),
	)
	return insns
}

// genIPv4CIDRCompare handles `field == 10.0.0.0/8` (and !=) in where.
// /32 collapses to a host compare; /0 with == is a no-op (always
// match) and /0 with != is unconditional reject.
func (c *whereCtx) genIPv4CIDRCompare(w *ir.Condition, anchor layerAnchor, fieldOff, fieldBytes int, failLabel string, jumpOp asm.JumpOp) (asm.Instructions, error) {
	if fieldBytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 CIDR needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, w.LiteralField.Layer.Spec.Name, w.LiteralField.Field.Name)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 32 {
		return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", prefix)
	}
	if prefix == 32 {
		expected := byteSwap(uint64(binary.BigEndian.Uint32(w.LiteralValue.V4[:])), 4)
		insns := emitFieldLoad(anchor, fieldOff, asm.Word)
		return append(insns, jumpOp.Imm(asm.R3, int32(expected), failLabel)), nil
	}
	if prefix == 0 {
		if w.LiteralOp == ast.CmpEq {
			return nil, nil
		}
		return asm.Instructions{asm.Ja.Label(failLabel)}, nil
	}
	maskBE := uint32(0xFFFFFFFF) << (32 - prefix)
	hostBE := binary.BigEndian.Uint32(w.LiteralValue.V4[:]) & maskBE
	maskLE := uint32(byteSwap(uint64(maskBE), 4))
	hostLE := uint32(byteSwap(uint64(hostBE), 4))
	return whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
		insns := emitFieldLoad(anchor, fieldOff, asm.Word)
		insns = append(insns, asm.And.Imm(asm.R3, int32(maskLE)))
		insns = append(insns, cmpRegEqU32(asm.JNE, hostLE, fail)...)
		return insns
	}), nil
}

// genIPv6CIDRCompare handles `field == 2001:db8::/32` (and !=) in
// where. Mirror of emitIPv6CIDRPredicate using absolute offsets.
func (c *whereCtx) genIPv6CIDRCompare(w *ir.Condition, anchor layerAnchor, fieldOff, fieldBytes int, failLabel string) (asm.Instructions, error) {
	if fieldBytes != 16 {
		return nil, fmt.Errorf("%w: IPv6 CIDR needs a 16-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, w.LiteralField.Layer.Spec.Name, w.LiteralField.Field.Name)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 128 {
		return nil, fmt.Errorf("codegen: IPv6 CIDR prefix %d out of [0,128]", prefix)
	}
	if prefix == 128 {
		highBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8])
		lowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16])
		return whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			return append(
				whereIPv6HalfCheck(anchor, fieldOff, ^uint64(0), highBE, fail),
				whereIPv6HalfCheck(anchor, fieldOff+8, ^uint64(0), lowBE, fail)...,
			)
		}), nil
	}
	if prefix == 0 {
		if w.LiteralOp == ast.CmpEq {
			return nil, nil
		}
		return asm.Instructions{asm.Ja.Label(failLabel)}, nil
	}
	maskHighBE, maskLowBE := ipv6PrefixMaskBE(prefix)
	hostHighBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8]) & maskHighBE
	hostLowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16]) & maskLowBE
	return whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
		var insns asm.Instructions
		if maskHighBE != 0 {
			insns = append(insns, whereIPv6HalfCheck(anchor, fieldOff, maskHighBE, hostHighBE, fail)...)
		}
		if maskLowBE != 0 {
			insns = append(insns, whereIPv6HalfCheck(anchor, fieldOff+8, maskLowBE, hostLowBE, fail)...)
		}
		return insns
	}), nil
}
