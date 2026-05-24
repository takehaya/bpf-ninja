package codegen

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
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
}

func (c *whereCtx) freshLabel(prefix string) string {
	c.labels++
	return fmt.Sprintf("dsl_%s_%d", prefix, c.labels)
}

// layerAnchorFor returns the addressing strategy for a layer's start
// in the scratch buffer, memoised after the first lookup. Layers
// flagged NeedsRuntimeOffset (resolver mark for "past a het-alt")
// route through their per-layer entry slot; the rest stay on the
// static R0+prefix path. Errors propagate from the static path
// (e.g. quantified layer in prefix) and from slot allocation
// (layer position exceeds the slot cap).
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
		slot, err = whereLayerEntrySlot(l.LayerPos)
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

// layerOffset is a thin wrapper preserved for callers that only need
// the static absolute offset (= they cannot handle slot anchors).
// New code should use layerAnchorFor and emitFieldLoad instead.
func (c *whereCtx) layerOffset(l *ir.LayerInstance) (int, error) {
	a, err := c.layerAnchorFor(l)
	if err != nil {
		return 0, err
	}
	if a.UseSlot {
		return 0, fmt.Errorf("%w: layer %q needs runtime offset but caller asked for a static prefix (likely option-walk past a het-alt — not yet wired)", ErrNotImplemented, layerSpecName(l))
	}
	return a.AbsOffset, nil
}

func layerSpecName(l *ir.LayerInstance) string {
	if l == nil || l.Spec == nil {
		return "<unnamed>"
	}
	return l.Spec.Name
}

// genCondition emits instructions that fall through when w evaluates
// to true and jump to failLabel when it evaluates to false. Errors
// surface with the condition's source position prefixed so users see
// which `where` atom blew up.
func genCondition(w *ir.Condition, lang LangCaps, p *ir.Program, qo queriedOptions, failLabel string) (asm.Instructions, error) {
	ctx := &whereCtx{p: p, lang: lang, anchors: make(map[*ir.LayerInstance]layerAnchor), queried: qo}
	insns, err := ctx.gen(w, failLabel)
	return insns, withPos(err, w.Pos)
}

func (c *whereCtx) gen(w *ir.Condition, failLabel string) (asm.Instructions, error) {
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
		return c.genArithCompare(w, failLabel)
	case ast.WAtomLiteralCmp:
		return c.genLiteralCompare(w, failLabel)
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
		return c.genBoolExists(w, failLabel)
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
	anchor, err := c.layerAnchorFor(w.BoolField.Layer)
	if err != nil {
		return nil, err
	}
	return emitAuxGating(w.BoolField.Aux.Gating, anchor, failLabel), nil
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
	leftInsns, err := c.genConditionAsBool(w.BoolL)
	if err != nil {
		return nil, err
	}
	rightInsns, err := c.genConditionAsBool(w.BoolR)
	if err != nil {
		return nil, err
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
	// Reuse the arith scratch slot 0; bool-eq doesn't nest with
	// arith binops in the resolved IR (parser produces them as
	// disjoint subtrees), so the slot is free at this point.
	slot := arithStackSlot(0)
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
//   inner emit (jump to `falsyLabel` on miss)
//   R3 = 1
//   Ja done
//   falsyLabel: R3 = 0
//   done:
//
// Used by genBoolEq so each operand of a Bool == Bool comparison is
// emitted exactly once.
func (c *whereCtx) genConditionAsBool(cond *ir.Condition) (asm.Instructions, error) {
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
	matchLabel := c.freshLabel("any_match")
	insns, err := c.genQuantUnroll(w, matchLabel, failLabel, true)
	if err != nil {
		return nil, err
	}
	// After all iterations exhaust without a match, fall to failLabel.
	insns = append(insns, asm.Ja.Label(failLabel))
	insns = append(insns, landingNoop(matchLabel))
	return insns, nil
}

// genAll emits a static-unroll where every iteration must succeed.
// Inner failure on any iteration jumps to failLabel directly; inner
// success continues to the next iteration. After all iterations
// succeed, control falls through.
func (c *whereCtx) genAll(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	if w.QuantTarget == nil {
		return nil, fmt.Errorf("codegen: all() lacks a resolved iteration target")
	}
	insns, err := c.genQuantUnroll(w, "" /* no per-iter accept */, failLabel, false)
	if err != nil {
		return nil, err
	}
	return insns, nil
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
	var insns asm.Instructions
	for i := 0; i < target.Capacity; i++ {
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

// genQuantIterBody clones the inner condition with the iterator
// FieldRef rebound to a static index for this iteration, then emits
// it. The fail target depends on anySemantics:
//   - any: per-iter mismatch → iterSkip (= "try next iter")
//   - all: per-iter mismatch → failLabel (= "all() fails")
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

// emitCountGuard emits the per-iteration check that the iteration
// index is below the runtime count. Primary-header byte (Owner == nil)
// reads from a layer-anchored field; owner-slot (Owner != nil) reads
// from the option's per-packet base via the dynamic-aux slot, with
// sentinel = option absent translating to "skip every iter" (vacuous
// any/all).
func (c *whereCtx) emitCountGuard(countSrc *quantCountSource, idx int, skipLabel string) (asm.Instructions, error) {
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
// Two shapes folded into one struct so emitCountGuard can dispatch on
// Owner == nil:
//   - Primary-header byte: Layer + ByteOff + Offset (e.g. SRv6
//     last_entry at byte 4, count = last_entry + 1).
//   - Owner option slot: Owner (the AuxLayout the slot maps to) +
//     ByteOff (= byte position of the length field within the
//     option, e.g. 1 for SACK) + SubBefore (bytes to subtract = the
//     option's fixed prefix size including kind+length) + RShAfter
//     (log2 of element size, e.g. 3 for 8-byte SACK blocks).
type quantCountSource struct {
	Layer     *ir.LayerInstance
	Owner     *vocab.AuxLayout
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
	target := w.QuantTarget
	var iterRef *ir.FieldRef
	ir.WalkConditionFieldRefs(w.Inner, func(ref *ir.FieldRef) {
		if iterRef == nil && ref != nil && ref.Aux != nil && ref.Aux.Stack != nil && ref.Aux.Stack.IsIterator {
			iterRef = ref
		}
	})
	if iterRef == nil {
		return nil, fmt.Errorf("codegen: quantifier inner has no iterator field reference")
	}
	if iterRef.Aux.OwnerOption != nil {
		// Length byte sits at slot+1 by RFC convention (kind=byte 0,
		// length=byte 1 for both TCP options and IPv4 options). The
		// raw length byte then has SubBefore=OffsetAfterOwner (the
		// option's fixed prefix) subtracted to get the trailing-array
		// byte count, which divides by ElemSize to yield the element
		// count. Examples:
		//   SACK   (OffsetAfterOwner=2, ElemSize=8): (length-2) >> 3 = 0..4 blocks
		//   RR     (OffsetAfterOwner=3, ElemSize=4): (length-3) >> 2 = 0..9 addrs
		shift := log2PowerOfTwo(target.ElemSize)
		if shift < 0 {
			return nil, fmt.Errorf("codegen: quantifier element size %d is not a power of two (cannot derive count via shift)", target.ElemSize)
		}
		return &quantCountSource{
			Layer:     iterRef.Layer,
			Owner:     iterRef.Aux.OwnerOption,
			ByteOff:   1,
			SubBefore: iterRef.Aux.OffsetAfterOwner,
			RShAfter:  shift,
		}, nil
	}
	if cnt := iterRef.Layer.Spec.StackCounts[target.OutParam]; cnt != nil {
		return &quantCountSource{
			Layer:   iterRef.Layer,
			ByteOff: cnt.ByteOff,
			Offset:  cnt.Addend,
		}, nil
	}
	// No @kunai_stack_count → caller unrolls over the static Capacity.
	return nil, nil
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

func rebindFieldRef(ref *ir.FieldRef, target *ir.QuantTarget, idx uint64) (*ir.FieldRef, error) {
	if ref == nil || ref.Aux == nil || ref.Aux.Stack == nil || !ref.Aux.Stack.IsIterator {
		return ref, nil
	}
	if ref.Aux.OutParam != target.OutParam {
		return nil, fmt.Errorf("codegen: iterator FieldRef references stack %q but quantifier target is %q", ref.Aux.OutParam, target.OutParam)
	}
	cp := *ref
	auxCopy := *ref.Aux
	auxCopy.Stack = &ir.StackIndex{
		Capacity: target.Capacity,
		IsStatic: true,
		Static:   idx,
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
//   <left with failLabel = tryRight>
//   Ja orDone
//   tryRight: <right with failLabel = failLabel>
//   orDone: <landing symbol>
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
//   <inner with failLabel = notSucc>
//   Ja failLabel    # inner succeeded → not fails
//   notSucc: <landing symbol>
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
//   - 0..15: 64-bit arith stack — genArithWithBits at depth d uses
//     slot d. The 64-bit and 128-bit paths never interleave within a
//     single binop emit, so the 128-bit path safely reuses slots in
//     this region for its own preserves: 0,1 for genArithCompare128's
//     LHS hold, 2,3 for genArith128's `field + field` LHS hi/lo, and
//     4 for genArithField128Load's high-half transient stash.
//
// The deepest slot (slot 15 at -176) writes bytes [-176, -168) and
// abuts bpfLoopCtxLayerEntrySlot's range [-184, -176) without
// overlap.
const (
	arithStackBase = -56
	maxArithDepth  = 16
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

	slot := arithStackSlot(0)
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
// (an Int<128> field) and `field + const` / `field - const` with the
// const treated as zero-extended Int<128> (its high half is 0).
// Anything more elaborate (field + field, nested binops, mul) returns
// ErrNotImplemented via genArith128.
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
//   - ArithField: 16-byte field load via genArithField128Load
//   - ArithConst: literal materialised as (0, const) (rare standalone)
//   - ArithBinOp with op ∈ {+, -}:
//     - `field op const`: const folded into low half, carry/borrow
//       propagated to high via a const-relative compare (no register
//       beyond R3/R5 needed).
//     - `field op field`: LHS preserved in arith slots 2/3 while RHS
//       is computed, then RHS is the in-place accumulator that LHS
//       gets added/subtracted into.
//
// Mul / div / mod on bit<128> stay ErrNotImplemented (F5 — bit-slice
// covers the practical IPv6 manipulation cases).
func (c *whereCtx) genArith128(e *ir.ArithExpr) (asm.Instructions, error) {
	if e == nil {
		return nil, fmt.Errorf("codegen: nil 128-bit arith expression")
	}
	switch e.Kind {
	case ast.ArithField:
		return c.genArithField128Load(e.Field)
	case ast.ArithBinOp:
		if e.Op != ast.ArithAdd && e.Op != ast.ArithSub {
			return nil, fmt.Errorf("%w: bit<128> arith binop %s is staged (F5)", ErrNotImplemented, e.Op)
		}
		if e.Right == nil {
			return nil, fmt.Errorf("codegen: bit<128> arith binop missing RHS")
		}
		switch e.Right.Kind {
		case ast.ArithConst:
			return c.genArith128FieldOpConst(e)
		case ast.ArithField:
			return c.genArith128FieldOpField(e)
		}
		return nil, fmt.Errorf("%w: bit<128> arith RHS shape %v not supported (only field or const)", ErrNotImplemented, e.Right.Kind)
	case ast.ArithConst:
		// Const-only arith expression at width > 64 is unusual but
		// we materialise it as (0, const). The const has been
		// resolver-narrowed to int32 territory upstream.
		return asm.Instructions{
			asm.Mov.Imm(asm.R3, 0),
			asm.Mov.Imm(asm.R5, int32(e.Const)),
		}, nil
	}
	return nil, fmt.Errorf("%w: bit<128> arith expression kind %v not supported", ErrNotImplemented, e.Kind)
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
func (c *whereCtx) genArith128FieldOpConst(e *ir.ArithExpr) (asm.Instructions, error) {
	imm := e.Right.Const
	if imm > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: bit<128> arith const exceeds int32 immediate range", ErrNotImplemented)
	}
	leftInsns, err := c.genArith128(e.Left)
	if err != nil {
		return nil, err
	}
	insns := append(asm.Instructions{}, leftInsns...)
	switch e.Op {
	case ast.ArithAdd:
		insns = append(insns, asm.Add.Imm(asm.R5, int32(imm)))
		noCarry := c.freshLabel("v128_nocarry")
		insns = append(insns, asm.JGE.Imm(asm.R5, int32(imm), noCarry))
		insns = append(insns, asm.Add.Imm(asm.R3, 1))
		insns = append(insns, landingNoop(noCarry))
	case ast.ArithSub:
		noBorrow := c.freshLabel("v128_noborrow")
		insns = append(insns, asm.JGE.Imm(asm.R5, int32(imm), noBorrow))
		insns = append(insns, asm.Sub.Imm(asm.R3, 1))
		insns = append(insns, landingNoop(noBorrow))
		insns = append(insns, asm.Sub.Imm(asm.R5, int32(imm)))
	}
	return insns, nil
}

// genArith128FieldOpField handles `field op field` at Int<128>. LHS
// is parked in arith slots 2/3 while RHS is computed; then we fold
// LHS into the R3/R5-resident RHS using stack-bridged register moves
// because kunai owns only R3/R5 inside the where pipeline (R6-R8 are
// host-callee-saved, R0/R4 carry packet pointers we mustn't trample).
//
// Output: R3 = (lhs_high + rhs_high + carry) mod 2^64,
//         R5 = (lhs_low  + rhs_low)            mod 2^64
// (mirrored for sub: borrow propagates from low to high).
func (c *whereCtx) genArith128FieldOpField(e *ir.ArithExpr) (asm.Instructions, error) {
	leftInsns, err := c.genArith128(e.Left)
	if err != nil {
		return nil, err
	}
	rightInsns, err := c.genArith128(e.Right)
	if err != nil {
		return nil, err
	}
	lhsHighSlot := arithStackSlot(2)
	lhsLowSlot := arithStackSlot(3)
	insns := append(asm.Instructions{}, leftInsns...)
	insns = append(insns,
		asm.StoreMem(asm.R10, lhsHighSlot, asm.R3, asm.DWord),
		asm.StoreMem(asm.R10, lhsLowSlot, asm.R5, asm.DWord),
	)
	insns = append(insns, rightInsns...)
	// R3 = rhs_high, R5 = rhs_low.
	switch e.Op {
	case ast.ArithAdd:
		// Park rhs_high so we can recycle R3 as the "load lhs into a
		// register" slot. R5 keeps rhs_low until we add lhs_low.
		insns = append(insns, asm.StoreMem(asm.R10, arithStackSlot(4), asm.R3, asm.DWord))
		insns = append(insns, asm.LoadMem(asm.R3, asm.R10, lhsLowSlot, asm.DWord)) // R3 = lhs_low
		insns = append(insns, asm.Add.Reg(asm.R5, asm.R3))                          // R5 = lhs_low + rhs_low
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
			asm.StoreMem(asm.R10, lhsLowSlot, asm.R5, asm.DWord), // park new_low briefly
			asm.LoadMem(asm.R3, asm.R10, arithStackSlot(4), asm.DWord), // R3 = rhs_high
			asm.LoadMem(asm.R5, asm.R10, lhsHighSlot, asm.DWord),        // R5 = lhs_high (carry-adjusted)
			asm.Add.Reg(asm.R3, asm.R5),                                 // R3 = rhs_high + lhs_high
			asm.LoadMem(asm.R5, asm.R10, lhsLowSlot, asm.DWord),         // R5 = new_low restored
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
			asm.Sub.Reg(asm.R3, asm.R5),                                 // R3 = lhs_low − rhs_low
			asm.StoreMem(asm.R10, lhsLowSlot, asm.R3, asm.DWord),        // park new_low
			asm.LoadMem(asm.R3, asm.R10, lhsHighSlot, asm.DWord),        // R3 = lhs_high (carry-adjusted)
			asm.LoadMem(asm.R5, asm.R10, arithStackSlot(4), asm.DWord),  // R5 = rhs_high
			asm.Sub.Reg(asm.R3, asm.R5),                                 // R3 = new_high
			asm.LoadMem(asm.R5, asm.R10, lhsLowSlot, asm.DWord),         // R5 = new_low
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

// genArith computes e's value into R3. depth indexes the stack slot
// used if e is a binary op; callers pass the current nesting level.
func (c *whereCtx) genArith(e *ir.ArithExpr, depth int) (asm.Instructions, error) {
	return c.genArithWithBits(e, depth, 0)
}

// genArithWithBits is genArith plus a target-width hint used to narrow
// integer-constant leaves at codegen time (dsl-types.md §5.2 / §7.3).
// targetBits = 0 means "no narrowing"; targetBits ∈ [1, 63] masks
// the constant to its low `targetBits` so 2's-complement negative
// literals fit the BPF int32 immediate.
func (c *whereCtx) genArithWithBits(e *ir.ArithExpr, depth int, targetBits int) (asm.Instructions, error) {
	if depth >= maxArithDepth {
		return nil, fmt.Errorf("%w: arith expression nested deeper than %d levels", ErrNotImplemented, maxArithDepth)
	}
	switch e.Kind {
	case ast.ArithConst:
		v := e.Const
		if targetBits > 0 && targetBits < 64 {
			v &= (uint64(1) << targetBits) - 1
		}
		if v > 0x7FFFFFFF {
			return nil, fmt.Errorf("%w: arith constant %d exceeds int32 immediate range", ErrNotImplemented, e.Const)
		}
		return asm.Instructions{asm.Mov.Imm(asm.R3, int32(v))}, nil
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
	if f.Aux != nil && f.Aux.Stack != nil && !f.Aux.Stack.IsStatic {
		// Dynamic stack index in a where clause: fold runtime offset
		// computation off the layer's where-context anchor, then
		// byte-swap the loaded value to natural order so downstream
		// arithmetic / comparison sees the network-order integer.
		anchor, err := c.layerAnchorFor(f.Layer)
		if err != nil {
			return nil, err
		}
		fieldBytes := f.Aux.FieldBitWidth / 8
		size, err := asmSizeFor(fieldBytes)
		if err != nil {
			return nil, err
		}
		addr, err := emitDynamicStackAddress(f, anchor, dslReject)
		if err != nil {
			return nil, err
		}
		fieldByteOff := f.Aux.FieldBitOff / 8
		insns := append(addr, asm.LoadMem(asm.R3, asm.R5, int16(fieldByteOff), size))
		if fieldBytes > 1 {
			insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
		}
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
		insns = append(insns, emitAuxGating(f.Aux.Gating, anchor, dslReject)...)
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
		if mask <= 0x7FFFFFFF {
			insns = append(insns, asm.And.Imm(asm.R3, int32(mask)))
		} else {
			insns = append(insns, asm.LoadImm(asm.R5, int64(mask), asm.DWord))
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
	left, err := c.genArith(e.Left, depth+1)
	if err != nil {
		return nil, err
	}
	right, err := c.genArith(e.Right, depth+1)
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
	return prefixHeaderSize(p, target, "where-clause field", uniformAltPrefixSize)
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
func prefixHeaderSize(p *ir.Program, until *ir.LayerInstance, reason string, altReducer func([]*ir.LayerInstance, string) (int, error)) (int, error) {
	total := 0
	for _, l := range p.Layers {
		if l == until {
			if l.Quant != ast.QuantOne {
				return 0, fmt.Errorf("%w: %s on quantified layer %q", ErrNotImplemented, reason, l.Spec.Name)
			}
			return total, nil
		}
		if l.Quant != ast.QuantOne {
			return 0, fmt.Errorf("%w: %s past quantified layer %q", ErrNotImplemented, reason, l.Spec.Name)
		}
		if l.Alternation != nil {
			altHs, err := altReducer(l.Alternation, reason)
			if err != nil {
				return 0, err
			}
			total += altHs
			continue
		}
		hs, err := headerSize(l.Spec)
		if err != nil {
			return 0, err
		}
		total += hs
	}
	if until != nil {
		return 0, fmt.Errorf("codegen: %s references layer %q which is not in program", reason, until.Spec.Name)
	}
	return total, nil
}

// prefixHeaderSizeMaxAlt is the capture-side wrapper that rounds
// heterogeneous alts up to their largest member instead of erroring.
func prefixHeaderSizeMaxAlt(p *ir.Program, until *ir.LayerInstance, reason string) (int, error) {
	return prefixHeaderSize(p, until, reason, maxAltPrefixSize)
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
//   - Dynamic stack indices route through emitDynamicStackAddress,
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
	if ref.Aux != nil && ref.Aux.Stack != nil && !ref.Aux.Stack.IsStatic {
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
	if ref.Aux.FieldBitOff%8 != 0 || ref.Aux.FieldBitWidth%8 != 0 {
		return nil, fmt.Errorf("%w: aux field %s.%s.%s not byte-aligned", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name)
	}
	fieldByteOff := int16(ref.Aux.FieldBitOff / 8)
	fieldBytes := ref.Aux.FieldBitWidth / 8

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
	insns := emitDynamicAuxByteLoad(slot, byteOff, size, dslReject)
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
	absOff, err := c.layerOffset(ref.Layer)
	if err != nil {
		return nil, err
	}
	anchor := absAnchor(absOff)
	if op == ast.CmpEq {
		addr, err := emitDynamicStackAddress(ref, anchor, failLabel)
		if err != nil {
			return nil, err
		}
		return append(addr, body(failLabel)...), nil
	}
	match := c.freshLabel("where_lit_match")
	addr, err := emitDynamicStackAddress(ref, anchor, match)
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
