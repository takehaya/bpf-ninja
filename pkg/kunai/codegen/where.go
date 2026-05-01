package codegen

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
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
	}
	return nil, fmt.Errorf("%w: where kind %s", ErrNotImplemented, w.Kind)
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
func (c *whereCtx) genArithFieldLoad(f *ir.FieldRef) (asm.Instructions, error) {
	absOff, err := c.layerOffset(f.Layer)
	if err != nil {
		return nil, err
	}
	fieldOff, fieldBytes, err := findFieldByteOffset(f.Layer.Spec, f.Field.Name)
	if err != nil {
		return nil, err
	}
	size, err := asmSizeFor(fieldBytes)
	if err != nil {
		return nil, err
	}
	total := int16(absOff + fieldOff)
	insns := asm.Instructions{asm.LoadMem(asm.R3, asm.R0, total, size)}
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
func (c *whereCtx) genLiteralCompare(w *ir.Condition, failLabel string) (asm.Instructions, error) {
	ref := w.LiteralField
	absOff, err := c.layerOffset(ref.Layer)
	if err != nil {
		return nil, err
	}
	bitOff, bits, err := findFieldBitOffset(ref.Layer.Spec, ref.Field.Name)
	if err != nil {
		return nil, err
	}
	if bitOff%8 != 0 || bits%8 != 0 {
		return nil, fmt.Errorf("%w: %s.%s is not byte-aligned (bit offset %d, %d bits)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Field.Name, bitOff, bits)
	}
	fieldOff := bitOff / 8
	fieldBytes := bits / 8
	base := int16(absOff + fieldOff)
	jumpOp, ok := ipEqualityJumpOp(w.LiteralOp)
	if !ok {
		return nil, fmt.Errorf("%w: network literal supports only == / != (got %s)", ErrNotImplemented, w.LiteralOp)
	}

	switch w.LiteralValue.Kind {
	case ast.ValIPv4:
		if fieldBytes != 4 {
			return nil, fmt.Errorf("%w: IPv4 literal needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		v4 := w.LiteralValue.V4
		expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
		insns := asm.Instructions{asm.LoadMem(asm.R3, asm.R0, base, asm.Word)}
		insns = append(insns, cmpRegEqU32(jumpOp, expected, failLabel)...)
		return insns, nil

	case ast.ValMAC:
		if fieldBytes != 6 {
			return nil, fmt.Errorf("%w: MAC literal needs a 6-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		mac := w.LiteralValue.MAC
		highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
		lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))
		return whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			insns := asm.Instructions{asm.LoadMem(asm.R3, asm.R0, base, asm.Word)}
			insns = append(insns, cmpRegEqU32(asm.JNE, highLE, fail)...)
			insns = append(insns, asm.LoadMem(asm.R3, asm.R0, base+4, asm.Half))
			insns = append(insns, cmpRegEqU16(asm.JNE, lowLE, fail)...)
			return insns
		}), nil

	case ast.ValIPv6:
		if fieldBytes != 16 {
			return nil, fmt.Errorf("%w: IPv6 literal needs a 16-byte field, got %d-byte %s.%s", ErrNotImplemented, fieldBytes, ref.Layer.Spec.Name, ref.Field.Name)
		}
		highBE := binary.BigEndian.Uint64(w.LiteralValue.V6[0:8])
		lowBE := binary.BigEndian.Uint64(w.LiteralValue.V6[8:16])
		return whereMultiWordRoute(c, w.LiteralOp, failLabel, func(fail string) asm.Instructions {
			return append(
				whereIPv6HalfCheck(base, ^uint64(0), highBE, fail),
				whereIPv6HalfCheck(base+8, ^uint64(0), lowBE, fail)...,
			)
		}), nil

	case ast.ValCIDR:
		if w.LiteralValue.AF == 4 {
			return c.genIPv4CIDRCompare(w, base, fieldBytes, failLabel, jumpOp)
		}
		return c.genIPv6CIDRCompare(w, base, fieldBytes, failLabel)
	}
	return nil, fmt.Errorf("%w: where literal kind %v", ErrNotImplemented, w.LiteralValue.Kind)
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
