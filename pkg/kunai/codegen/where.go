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
// or/not branches get unique landings, and a memoized layer-offset
// cache.
type whereCtx struct {
	p       *ir.Program
	caps    Capabilities
	labels  int
	offsets map[*ir.LayerInstance]int
}

func (c *whereCtx) freshLabel(prefix string) string {
	c.labels++
	return fmt.Sprintf("dsl_%s_%d", prefix, c.labels)
}

// layerOffset returns the absolute scratch-buffer offset of a layer,
// memoised after the first lookup. Also propagates the "past a
// quantifier" error from layerAbsoluteOffset.
func (c *whereCtx) layerOffset(l *ir.LayerInstance) (int, error) {
	if off, ok := c.offsets[l]; ok {
		return off, nil
	}
	off, err := layerAbsoluteOffset(l, c.p)
	if err != nil {
		return 0, err
	}
	c.offsets[l] = off
	return off, nil
}

// genCondition emits instructions that fall through when w evaluates
// to true and jump to failLabel when it evaluates to false. Errors
// surface with the condition's source position prefixed so users see
// which `where` atom blew up.
func genCondition(w *ir.Condition, caps Capabilities, p *ir.Program, failLabel string) (asm.Instructions, error) {
	ctx := &whereCtx{p: p, caps: caps, offsets: make(map[*ir.LayerInstance]int)}
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
		return genActionAtom(w, c.caps, failLabel)
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
	}
	return nil, fmt.Errorf("%w: where kind %s", ErrNotImplemented, w.Kind)
}

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
			guard, err := c.emitCountGuard(countSrc, i, iterSkip, anySemantics, failLabel)
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
// index is below the runtime count. countSrc.Field is a primary
// header field of the stack's owning layer (e.g. srv6.last_entry +
// 1 for SRv6 segments — the +1 is folded into the offset).
func (c *whereCtx) emitCountGuard(countSrc *quantCountSource, idx int, skipLabel string, anySemantics bool, failLabel string) (asm.Instructions, error) {
	absOff, err := c.layerOffset(countSrc.Layer)
	if err != nil {
		return nil, err
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R3, asm.R0, int16(absOff+countSrc.ByteOff), asm.Byte),
		asm.Add.Imm(asm.R3, int32(countSrc.Offset)),
		// `if R3 <= idx: skip` → `if R3 < idx+1: skip` → JLE.Imm(R3, idx, skip).
		asm.JLE.Imm(asm.R3, int32(idx), skipLabel),
	}
	_ = anySemantics
	_ = failLabel
	return insns, nil
}

// quantCountSource carries the runtime count of an aux header stack:
// a primary-header byte field plus an offset (e.g. last_entry + 1 for
// SRv6). nil means "no known count" — codegen falls back to static
// unroll over the full Capacity.
type quantCountSource struct {
	Layer   *ir.LayerInstance
	ByteOff int
	Offset  int // value to add to the loaded byte (= +1 for last_entry → count)
}

// stackCountSource derives a runtime count for the quantifier
// target's stack. For SRv6 (the only count-driven stack in the
// bundled vocab today) the count is `srv6.last_entry + 1`; the
// byte offset of last_entry inside srv6_h is fixed. Other stacks
// return nil so the unroll runs over the full Capacity (which is
// safe for self-flag chains where the parser has already walked
// every entry).
func stackCountSource(w *ir.Condition) (*quantCountSource, error) {
	target := w.QuantTarget
	// We need a layer to anchor the count source; pick it from the
	// first iterator FieldRef inside the inner condition.
	var iterRef *ir.FieldRef
	ir.WalkConditionFieldRefs(w.Inner, func(ref *ir.FieldRef) {
		if iterRef == nil && ref != nil && ref.Aux != nil && ref.Aux.Stack != nil && ref.Aux.Stack.IsIterator {
			iterRef = ref
		}
	})
	if iterRef == nil {
		return nil, fmt.Errorf("codegen: quantifier inner has no iterator field reference")
	}
	if iterRef.Layer.Spec.Name == "srv6" && target.OutParam == "segments" {
		// last_entry is byte 4 of srv6_h. count = last_entry + 1.
		return &quantCountSource{Layer: iterRef.Layer, ByteOff: 4, Offset: 1}, nil
	}
	// No known count source: caller falls back to full Capacity unroll.
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
const (
	arithStackBase = -56
	maxArithDepth  = 4
)

// genArithCompare emits code for "arith CmpOp arith". Left operand
// ends up in R5, right in R3; the reject-direction jump covers the
// failure branch.
func (c *whereCtx) genArithCompare(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	left, err := c.genArith(w.ArithL, 0)
	if err != nil {
		return nil, err
	}
	right, err := c.genArith(w.ArithR, 0)
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

// genArith computes e's value into R3. depth indexes the stack slot
// used if e is a binary op; callers pass the current nesting level.
func (c *whereCtx) genArith(e *ir.ArithExpr, depth int) (asm.Instructions, error) {
	if depth >= maxArithDepth {
		return nil, fmt.Errorf("%w: arith expression nested deeper than %d levels", ErrNotImplemented, maxArithDepth)
	}
	switch e.Kind {
	case ast.ArithConst:
		if e.Const > 0x7FFFFFFF {
			return nil, fmt.Errorf("%w: arith constant %d exceeds int32 immediate range", ErrNotImplemented, e.Const)
		}
		return asm.Instructions{asm.Mov.Imm(asm.R3, int32(e.Const))}, nil
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
	if f.Aux != nil && f.Aux.Option != nil {
		return c.genOptionLookupLoad(f)
	}
	if f.Aux != nil && f.Aux.Stack != nil && !f.Aux.Stack.IsStatic {
		// Dynamic stack index in a where clause: fold runtime offset
		// computation, then byte-swap the loaded value to natural
		// order so downstream arithmetic / comparison sees the
		// network-order integer.
		fieldBytes := f.Aux.FieldBitWidth / 8
		size, err := asmSizeFor(fieldBytes)
		if err != nil {
			return nil, err
		}
		insns, err := emitDynamicStackLoad(f, size, dslReject)
		if err != nil {
			return nil, err
		}
		if fieldBytes > 1 {
			insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
		}
		return insns, nil
	}
	absOff, err := c.layerOffset(f.Layer)
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
		insns = append(insns, emitAuxGating(f.Aux.Gating, absAnchor(absOff), dslReject)...)
	}
	total := int16(absOff + fieldOff)
	insns = append(insns, asm.LoadMem(asm.R3, asm.R0, total, size))
	if fieldBytes > 1 {
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	return insns, nil
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
	}
	return 0, fmt.Errorf("codegen: unknown arith op %v", op)
}

// layerAbsoluteOffset returns the scratch-buffer byte offset at which
// target's header begins.
func layerAbsoluteOffset(target *ir.LayerInstance, p *ir.Program) (int, error) {
	return prefixHeaderSize(p, target, "where-clause field")
}

// prefixHeaderSize sums header sizes of p.Layers up to (but not
// including) until. If until is nil every layer is summed. Any
// quantified layer in the traversed range — including until itself —
// fails with ErrNotImplemented, because the prefix length would
// otherwise be runtime-variable. reason is surfaced verbatim in the
// error message ("where-clause field", "capture headers", ...).
func prefixHeaderSize(p *ir.Program, until *ir.LayerInstance, reason string) (int, error) {
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

// genActionAtom emits the load+compare for `where action == NAME`.
// The host capability supplies (a) the integer the symbolic NAME
// compares against and (b) instructions that materialise the action
// u32 in R3. When caps disable action atoms (Action map nil or
// fetcher nil) this returns ErrNotImplemented — the resolver
// normally catches that earlier with a clearer message.
func genActionAtom(w *ir.Condition, caps Capabilities, failLabel string) (asm.Instructions, error) {
	if !caps.HasActionAtoms() {
		return nil, fmt.Errorf("%w: `action == %s` is not available on this host (caps.Action is nil)", ErrNotImplemented, w.ActionValue)
	}
	val, ok := caps.Action[w.ActionValue]
	if !ok {
		return nil, fmt.Errorf("codegen: unknown action %q (host caps.Action has %d entries)", w.ActionValue, len(caps.Action))
	}
	insns := caps.ActionFetcher.EmitFetch(asm.R3)
	return append(insns, asm.JNE.Imm(asm.R3, val, failLabel)), nil
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
	ref := w.LiteralField
	jumpOp, ok := ipEqualityJumpOp(w.LiteralOp)
	if !ok {
		return nil, fmt.Errorf("%w: network literal supports only == / != (got %s)", ErrNotImplemented, w.LiteralOp)
	}
	if ref.Aux != nil && ref.Aux.Stack != nil && !ref.Aux.Stack.IsStatic {
		return c.genLiteralCompareDynamic(w, failLabel)
	}
	absOff, err := c.layerOffset(ref.Layer)
	if err != nil {
		return nil, err
	}
	fieldOff, fieldBytes, err := whereLiteralFieldOffset(ref)
	if err != nil {
		return nil, err
	}
	base := int16(absOff + fieldOff)

	var prelude asm.Instructions
	if ref.Aux != nil {
		prelude = emitAuxGating(ref.Aux.Gating, absAnchor(absOff), failLabel)
	}

	switch w.LiteralValue.Kind {
	case ast.ValIPv4:
		if fieldBytes != 4 {
			return nil, fmt.Errorf("%w: IPv4 literal needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		v4 := w.LiteralValue.V4
		expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, asm.LoadMem(asm.R3, asm.R0, base, asm.Word))
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
			insns := asm.Instructions{asm.LoadMem(asm.R3, asm.R0, base, asm.Word)}
			insns = append(insns, cmpRegEqU32(asm.JNE, highLE, fail)...)
			insns = append(insns, asm.LoadMem(asm.R3, asm.R0, base+4, asm.Half))
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
				whereIPv6HalfCheck(base, ^uint64(0), highBE, fail),
				whereIPv6HalfCheck(base+8, ^uint64(0), lowBE, fail)...,
			)
		})...), nil

	case ast.ValCIDR:
		if ref.Aux != nil {
			return nil, fmt.Errorf("%w: CIDR literal predicate on auxiliary header field is not yet supported", ErrNotImplemented)
		}
		if w.LiteralValue.AF == 4 {
			return c.genIPv4CIDRCompare(w, base, fieldBytes, failLabel, jumpOp)
		}
		return c.genIPv6CIDRCompare(w, base, fieldBytes, failLabel)
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
	}
	return nil, fmt.Errorf("%w: dynamic-index aux compare for literal kind %v", ErrNotImplemented, w.LiteralValue.Kind)
}

// genOptionLookupLoad emits a TCP/IPv4 option walk that scans the
// option list for the kind discriminator named by ref.Aux.Option,
// then loads the addressed field bytes into R3 (with HostTo(BE) for
// multi-byte fields so downstream comparison sees natural-order
// integers). Failure (option not found, or end of options reached
// without a match) jumps to dslReject.
//
// The walk is a static unroll capped at optionWalkMaxIters (= 20):
// max options area is 40 bytes, min option size is 1 byte, so 20
// iterations conservatively covers every real packet. Each iter
// reads one byte (the kind discriminator) and dispatches:
//   - kind == TerminatorKind → fail (no more options, target absent)
//   - kind == PaddingKind    → advance 1 byte, next iter
//   - kind == OptionKind     → match, exit walk and read field
//   - otherwise              → advance by length byte, next iter
//
// Layer location anchor: where-clause field loads compute the
// layer's absolute byte offset via c.layerOffset. The walk threads
// that absolute offset into R2 each iter so register-relative LDX
// can address bytes without re-deriving R0 + offset every time.
//
// Out-of-this-MVP:
//   - .exists predicates land via a different shape (return bool
//     into a register without a downstream LDX); this commit only
//     handles ExistsOnly = false.
//   - bracket-predicate / R4-anchored callers (predicate.go) do not
//     route here; option access from inside a layer's bracket
//     predicate is rare and surfaces ErrNotImplemented from
//     fieldRefByteOffset until a follow-up plumbs it.
const optionWalkMaxIters = 20

func (c *whereCtx) genOptionLookupLoad(ref *ir.FieldRef) (asm.Instructions, error) {
	aux := ref.Aux
	opt := aux.Option
	if opt.ExistsOnly {
		return nil, fmt.Errorf("%w: option `%s.options.%s.exists` codegen needs the bool-atom parser extension", ErrNotImplemented, ref.Layer.Spec.Name, opt.Name)
	}
	vs := ref.Layer.Spec.VariableSuffix
	if vs == nil {
		return nil, fmt.Errorf("%w: option lookup needs %q to declare a VAREXT_LEN_* (options length source)", ErrNotImplemented, ref.Layer.Spec.Name)
	}
	primaryBits := vocab.SumBits(ref.Layer.Spec.Fields)
	if primaryBits%8 != 0 {
		return nil, fmt.Errorf("%w: layer %q primary header is %d bits (not byte-aligned)", ErrNotImplemented, ref.Layer.Spec.Name, primaryBits)
	}
	primarySize := primaryBits / 8

	absOff, err := c.layerOffset(ref.Layer)
	if err != nil {
		return nil, err
	}
	if aux.FieldBitOff%8 != 0 || aux.FieldBitWidth%8 != 0 {
		return nil, fmt.Errorf("%w: option field %s.%s.%s not byte-aligned (bit-off %d, %d bits)", ErrNotImplemented, ref.Layer.Spec.Name, opt.Name, ref.Field.Name, aux.FieldBitOff, aux.FieldBitWidth)
	}
	fieldByteOff := aux.FieldBitOff / 8
	fieldBytes := aux.FieldBitWidth / 8
	size, err := asmSizeFor(fieldBytes)
	if err != nil {
		return nil, err
	}

	foundLabel := c.freshLabel("opt_found")
	// staticUpperBound is the layer-header-end ceiling: primarySize +
	// max options bytes (40 for both TCP and IPv4). Clamping R4 (=
	// options_end) to this constant once gives the verifier a tight
	// upper bound that propagates to R3 across the JGE.Reg compare —
	// without the clamp, the verifier cannot infer R3 < scratch_size
	// from a register-vs-register compare and the post-walk LDX is
	// rejected with "R2 max value is outside the allowed memory range".
	staticUpperBound := primarySize + 40

	var insns asm.Instructions
	// R3 = current option offset (layer-relative); start at primarySize.
	// R4 = options_end (layer-relative) — caller-saved scratch in where
	//      context (offsetBase is dead here), reused throughout the walk.
	// R5 = scratch for the per-iter kind / length byte.
	// R2 = address of the current option's first byte (= R0+absOff+R3),
	//      stable across kind and length loads in the same iter.
	insns = append(insns, asm.Mov.Imm(asm.R3, int32(primarySize)))
	insns = append(insns,
		asm.LoadMem(asm.R4, asm.R0, int16(absOff+vs.LenByteOff), asm.Byte),
		asm.And.Imm(asm.R4, int32(vs.LenMask)),
	)
	if vs.LenShift > 0 {
		insns = append(insns, asm.RSh.Imm(asm.R4, int32(vs.LenShift)))
	}
	if vs.Scale > 1 {
		insns = append(insns, asm.Mul.Imm(asm.R4, int32(vs.Scale)))
	}
	insns = append(insns,
		asm.JLT.Imm(asm.R4, int32(primarySize), dslReject),
		asm.JGT.Imm(asm.R4, int32(staticUpperBound), dslReject),
	)

	for i := 0; i < optionWalkMaxIters; i++ {
		notPad := c.freshLabel("opt_not_pad")
		nextIter := c.freshLabel("opt_iter_done")

		insns = append(insns,
			asm.JGE.Reg(asm.R3, asm.R4, dslReject),
			// Per-iter constant cap: lets the verifier infer R3.umax
			// across iterations. The single setup-time `R4 <= staticUB`
			// clamp (above) is not enough because the verifier loses
			// the propagated bound through Add.Reg in each iter.
			asm.JGE.Imm(asm.R3, int32(staticUpperBound), dslReject),
			asm.Mov.Reg(asm.R2, asm.R0),
			asm.Add.Imm(asm.R2, int32(absOff)),
			asm.Add.Reg(asm.R2, asm.R3),
			asm.LoadMem(asm.R5, asm.R2, 0, asm.Byte),
			asm.JEq.Imm(asm.R5, int32(opt.TerminatorKind), dslReject),
			asm.JNE.Imm(asm.R5, int32(opt.PaddingKind), notPad),
			asm.Add.Imm(asm.R3, 1),
			asm.Ja.Label(nextIter),
			landingNoop(notPad),
			asm.JEq.Imm(asm.R5, int32(opt.Kind), foundLabel),
			asm.LoadMem(asm.R5, asm.R2, int16(opt.LengthByteOff), asm.Byte),
			asm.JLT.Imm(asm.R5, 2, dslReject),
			asm.Add.Reg(asm.R3, asm.R5),
			landingNoop(nextIter),
		)
	}
	insns = append(insns, asm.Ja.Label(dslReject))

	// Match landing: R2 still points at the addressed option's first
	// byte (the kind dispatch did not clobber it), so the field LDX
	// reuses it without recomputing the address.
	insns = append(insns, landingNoop(foundLabel))
	insns = append(insns, asm.LoadMem(asm.R3, asm.R2, int16(fieldByteOff), size))
	if fieldBytes > 1 {
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	return insns, nil
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
func whereIPv6HalfCheck(base int16, mask, host uint64, failLabel string) asm.Instructions {
	insns := asm.Instructions{
		asm.LoadMem(asm.R3, asm.R0, base, asm.DWord),
	}
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
func (c *whereCtx) genIPv4CIDRCompare(w *ir.Condition, base int16, fieldBytes int, failLabel string, jumpOp asm.JumpOp) (asm.Instructions, error) {
	if fieldBytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 CIDR needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, w.LiteralField.Layer.Spec.Name, w.LiteralField.Field.Name)
	}
	prefix := w.LiteralValue.Prefix
	if prefix < 0 || prefix > 32 {
		return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", prefix)
	}
	if prefix == 32 {
		expected := byteSwap(uint64(binary.BigEndian.Uint32(w.LiteralValue.V4[:])), 4)
		return asm.Instructions{
			asm.LoadMem(asm.R3, asm.R0, base, asm.Word),
			jumpOp.Imm(asm.R3, int32(expected), failLabel),
		}, nil
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
		insns := asm.Instructions{
			asm.LoadMem(asm.R3, asm.R0, base, asm.Word),
			asm.And.Imm(asm.R3, int32(maskLE)),
		}
		insns = append(insns, cmpRegEqU32(asm.JNE, hostLE, fail)...)
		return insns
	}), nil
}

// genIPv6CIDRCompare handles `field == 2001:db8::/32` (and !=) in
// where. Mirror of emitIPv6CIDRPredicate using absolute offsets.
func (c *whereCtx) genIPv6CIDRCompare(w *ir.Condition, base int16, fieldBytes int, failLabel string) (asm.Instructions, error) {
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
				whereIPv6HalfCheck(base, ^uint64(0), highBE, fail),
				whereIPv6HalfCheck(base+8, ^uint64(0), lowBE, fail)...,
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
			insns = append(insns, whereIPv6HalfCheck(base, maskHighBE, hostHighBE, fail)...)
		}
		if maskLowBE != 0 {
			insns = append(insns, whereIPv6HalfCheck(base+8, maskLowBE, hostLowBE, fail)...)
		}
		return insns
	}), nil
}
