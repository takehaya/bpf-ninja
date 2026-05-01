package resolve

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// checkLiteralWidthShape pins the network-literal RHS (or LHS) to a
// field whose declared bit width can hold it: IPv4 / CIDR-v4 →
// bit<32>, IPv6 / CIDR-v6 → bit<128>, MAC → bit<48>. Mismatches
// surface via errLiteralFieldShape so the user gets a clear
// diagnostic before codegen. dsl-types.md §7.5.
func checkLiteralWidthShape(ref *ir.FieldRef, v *ast.Value, pos ast.Position) error {
	want := 0
	desc := ""
	switch v.Kind {
	case ast.ValIPv4:
		want, desc = 32, "IPv4 address"
	case ast.ValIPv6:
		want, desc = 128, "IPv6 address"
	case ast.ValMAC:
		want, desc = 48, "MAC address"
	case ast.ValCIDR:
		if v.AF == 4 {
			want, desc = 32, "IPv4 CIDR"
		} else {
			want, desc = 128, "IPv6 CIDR"
		}
	default:
		return errorf(pos, "internal: %v is not a network literal", v.Kind)
	}
	if ref.Field.Bits != want {
		return errLiteralFieldShape(pos, desc, want, ref)
	}
	return nil
}

// checkBracketIntFit covers the bracket-predicate variant of the
// literal narrow check (dsl-types.md §7.2 row "Bracket predicate"):
// `tcp[dport == V]` rejects V whose value cannot be narrowed to the
// field's declared bit width. The fit predicate is shared with the
// arith-context check (uintFitsBits) so signed-extended negative
// literals (e.g. `dport == -1` ⇒ stored as 0xffff..ff) are accepted
// when they would land in the field's `[-2^(N-1), 2^N)` range
// (dsl-types.md §7.3). Returns nil if the predicate is not a shape
// that needs this check (non-int literal, no field, or wide enough
// field).
func checkBracketIntFit(field *ir.FieldRef, v *ast.Value, layerName string, pos ast.Position) error {
	if v == nil || v.Kind != ast.ValInt || field.Field == nil {
		return nil
	}
	bits := field.Field.Bits
	if uintFitsBits(v.Int, bits) {
		return nil
	}
	fieldName := field.Field.Name
	if field.Aux != nil {
		fieldName = field.Aux.OutParam + "." + fieldName
	}
	return errFitInField(pos, v.Int, bits, layerName, fieldName)
}

// typing.go implements the static type checks defined by
// docs/ja/dsl-types.md. Per D0 (b+1) the resolver enforces fit-check
// and division-by-zero rules; codegen separately reports
// ErrNotImplemented for staged operations on Int<N> with N > 64.

// checkArithCondition runs all type-related validations against a
// resolved WAtomArith condition: literal fit checks against the
// inferred target width and static divide-by-zero detection.
func checkArithCondition(c *ir.Condition) error {
	if c == nil {
		return nil
	}
	bits := arithCmpTargetBits(c)
	if bits == 0 {
		bits = 64
	}
	if err := checkArithExpr(c.ArithL, bits); err != nil {
		return err
	}
	if err := checkArithExpr(c.ArithR, bits); err != nil {
		return err
	}
	return nil
}

// checkArithExpr walks an arith subtree and applies fit checks plus
// static div/mod-by-zero detection. `bits` is the target width that
// integer literals at the leaves must fit into; for div/mod RHS the
// width is irrelevant — `0` is rejected unconditionally.
func checkArithExpr(e *ir.ArithExpr, bits int) error {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case ast.ArithConst:
		if !uintFitsBits(e.Const, bits) {
			return errFitInArith(e.Pos, e.Const, bits)
		}
	case ast.ArithField:
		// Field references are typed by their declared bit width;
		// nothing to check here.
	case ast.ArithBinOp:
		if (e.Op == ast.ArithDiv || e.Op == ast.ArithMod) && isZeroLiteral(e.Right) {
			return errStaticDivZero(e.Pos, e.Op)
		}
		if err := checkArithExpr(e.Left, bits); err != nil {
			return err
		}
		if err := checkArithExpr(e.Right, bits); err != nil {
			return err
		}
	}
	return nil
}

// arithCmpTargetBits picks the comparison's target width per the
// uniform widening rule (dsl-types.md §5.2): the wider operand wins,
// or the field operand wins when one side is a literal. Returns 0 if
// no field is reachable from either side (purely literal expression),
// in which case the caller should fall back to 64-bit fit checking.
func arithCmpTargetBits(c *ir.Condition) int {
	lBits := exprMaxFieldBits(c.ArithL)
	rBits := exprMaxFieldBits(c.ArithR)
	switch {
	case lBits == 0 && rBits == 0:
		return 0
	case lBits == 0:
		return rBits
	case rBits == 0:
		return lBits
	default:
		if lBits > rBits {
			return lBits
		}
		return rBits
	}
}

// exprMaxFieldBits returns the largest declared bit width of any
// field reachable from an arith expression. Returns 0 if the
// expression has no field references (literal-only or nil).
func exprMaxFieldBits(e *ir.ArithExpr) int {
	if e == nil {
		return 0
	}
	switch e.Kind {
	case ast.ArithField:
		return fieldRefBits(e.Field)
	case ast.ArithBinOp:
		l := exprMaxFieldBits(e.Left)
		r := exprMaxFieldBits(e.Right)
		if l > r {
			return l
		}
		return r
	}
	return 0
}

// fieldRefBits returns the declared bit width of a FieldRef. Aux
// references use the aux header's field bit window; primary
// references use the field's declared width.
func fieldRefBits(ref *ir.FieldRef) int {
	if ref == nil {
		return 0
	}
	if ref.Aux != nil {
		return ref.Aux.FieldBitWidth
	}
	if ref.Field != nil {
		return ref.Field.Bits
	}
	return 0
}

// uintFitsBits reports whether a uint64 literal fits in the unsigned
// range [0, 2^bits). Negative literals reach this helper as their
// 2's-complement uint64 representation, in which case the fit check
// passes when the original signed value lies in [-2^(bits-1), 0).
// We approximate by accepting any value where the high bits beyond
// the target width are either all zero or all one (= a sign-extended
// negative). Both intents are consistent with dsl-types.md §7.3.
func uintFitsBits(v uint64, bits int) bool {
	if bits <= 0 || bits >= 64 {
		return true
	}
	mask := uint64(1)<<bits - 1
	low := v & mask
	high := v >> bits
	if high == 0 {
		return true
	}
	// Sign-extended negative literal: high bits must equal the
	// complement of the mask (all ones above the target width AND
	// the sign bit set in the low half).
	signBit := uint64(1) << (bits - 1)
	if low&signBit == 0 {
		return false
	}
	return high == ^uint64(0)>>bits
}

func isZeroLiteral(e *ir.ArithExpr) bool {
	return e != nil && e.Kind == ast.ArithConst && e.Const == 0
}
