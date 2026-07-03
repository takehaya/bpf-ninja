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
		return e.Field.EffectiveBits()
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

// detachTrailingSlice peels a `[lo:hi]` slice index off the last
// segment of fp so the existing dispatch logic in
// resolveQualifiedField / resolveUnqualifiedField doesn't choke on
// it as a forbidden trailing index. The returned FieldPath shares
// the original Parts slice but truncates Indices when the last
// slot held a slice. The caller re-attaches the slice to the
// resolved FieldRef via attachSlice.
//
// Also performs the byte-aligned MVP check (lo % 8 == 0,
// hi % 8 == 0); non-aligned ranges surface as ErrNotImplemented
// once F11 lands a shift+mask emit.
func detachTrailingSlice(fp *ast.FieldPath) (*ast.FieldPath, *ast.IndexExpr, error) {
	if fp == nil || len(fp.Parts) == 0 || len(fp.Indices) == 0 {
		return fp, nil, nil
	}
	// Indices is parallel to Parts but may be shorter when the
	// trailing segment has no `[…]` attached. Bound-check both
	// before peeking at the trailing slot.
	last := len(fp.Parts) - 1
	if last >= len(fp.Indices) {
		return fp, nil, nil
	}
	idx := fp.Indices[last]
	if idx == nil || !idx.IsSlice {
		return fp, nil, nil
	}
	// dsl-types.md §3.4 allows arbitrary lo / hi as long as the
	// resulting width fits the codegen's load-and-mask path. The
	// field-aware alignment / range validation runs in attachSlice
	// once the FieldRef is known.
	cleaned := *fp
	cleaned.Indices = append([]*ast.IndexExpr(nil), fp.Indices...)
	cleaned.Indices[last] = nil
	return &cleaned, idx, nil
}

// tryDesugarMultiLDXSliceCmp converts a `slice == slice` (or `!=`)
// comparison whose width exceeds a single LDX into an AND / OR of
// LDX-sized sub-comparisons. Returns nil when the pattern doesn't
// match, in which case the caller proceeds with the regular cmp
// emit.
//
// Mechanics: split the slice's bit range from `lo` greedily into
// LDX-aligned chunks (8 / 4 / 2 / 1 bytes), build a per-chunk cmp
// Condition, and combine left-to-right with WAnd (for ==) or WOr
// (for !=). Each sub-cmp targets a single-LDX-sized slice on each
// side so the existing 64-bit pipeline handles them without any
// new emit. byte-aligned slices in (64, 128) (e.g. [0:96]) are
// the obvious win; degenerate widths like 88 (= 8+2+1 bytes) work
// too via 3-way split.
func tryDesugarMultiLDXSliceCmp(al, ar *ir.ArithExpr, op ast.CmpOp, pos ast.Position) *ir.Condition {
	if al == nil || ar == nil {
		return nil
	}
	if al.Kind != ast.ArithField || ar.Kind != ast.ArithField {
		return nil
	}
	if al.Field == nil || ar.Field == nil {
		return nil
	}
	if al.Field.Slice == nil || ar.Field.Slice == nil {
		return nil
	}
	if op != ast.CmpEq && op != ast.CmpNeq {
		return nil
	}
	lWidth := al.Field.Slice.Bits()
	rWidth := ar.Field.Slice.Bits()
	if lWidth != rWidth {
		return nil
	}
	if lWidth <= 64 {
		// Fits a single LDX; no desugar needed.
		return nil
	}
	chunks := splitSliceIntoLDXChunks(lWidth)
	if len(chunks) <= 1 {
		return nil
	}
	conds := make([]*ir.Condition, 0, len(chunks))
	for _, ch := range chunks {
		lhsRef := cloneFieldRefWithSlice(al.Field, al.Field.Slice.Lo+ch.lo, al.Field.Slice.Lo+ch.hi)
		rhsRef := cloneFieldRefWithSlice(ar.Field, ar.Field.Slice.Lo+ch.lo, ar.Field.Slice.Lo+ch.hi)
		conds = append(conds, &ir.Condition{
			Kind:   ast.WAtomArith,
			ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: lhsRef, Pos: pos},
			ArithR: &ir.ArithExpr{Kind: ast.ArithField, Field: rhsRef, Pos: pos},
			Op:     op,
			Pos:    pos,
		})
	}
	combiner := ast.WAnd
	if op == ast.CmpNeq {
		combiner = ast.WOr
	}
	return combineConditions(conds, combiner, pos)
}

// chunk is a half-open bit range produced by splitSliceIntoLDXChunks.
type chunk struct {
	lo, hi int
}

// splitSliceIntoLDXChunks divides a width-bit byte-aligned range
// into chunks each fitting a single asmSizeFor-acceptable LDX
// (8 / 4 / 2 / 1 bytes). Greedy from the start. Width must be a
// multiple of 8; the caller's byte-aligned check (in attachSlice)
// guarantees this.
func splitSliceIntoLDXChunks(width int) []chunk {
	var chunks []chunk
	pos := 0
	for pos < width {
		bytesLeft := (width - pos) / 8
		var chunkBytes int
		switch {
		case bytesLeft >= 8:
			chunkBytes = 8
		case bytesLeft >= 4:
			chunkBytes = 4
		case bytesLeft >= 2:
			chunkBytes = 2
		default:
			chunkBytes = 1
		}
		chunks = append(chunks, chunk{lo: pos, hi: pos + chunkBytes*8})
		pos += chunkBytes * 8
	}
	return chunks
}

// cloneFieldRefWithSlice returns a shallow copy of orig with its
// Slice field replaced by [lo, hi). Layer / Field / Aux pointers
// are preserved so downstream codegen finds the same vocab metadata.
func cloneFieldRefWithSlice(orig *ir.FieldRef, lo, hi int) *ir.FieldRef {
	cp := *orig
	cp.Slice = &ir.FieldSlice{Lo: lo, Hi: hi}
	return &cp
}

// combineConditions folds conds left-to-right with kind ∈ {WAnd, WOr}.
// Caller guarantees len(conds) ≥ 1.
func combineConditions(conds []*ir.Condition, kind ast.WhereKind, pos ast.Position) *ir.Condition {
	result := conds[0]
	for _, c := range conds[1:] {
		result = &ir.Condition{Kind: kind, Left: result, Right: c, Pos: pos}
	}
	return result
}

// attachSlice validates a detached `[lo:hi]` slice against the
// resolved FieldRef's underlying width and pins it on the ref.
func attachSlice(ref *ir.FieldRef, slice *ast.IndexExpr) error {
	if ref == nil || slice == nil {
		return nil
	}
	width := 0
	switch {
	case ref.Aux != nil:
		width = ref.Aux.FieldBitWidth
	case ref.Field != nil:
		width = ref.Field.Bits
	}
	if width == 0 {
		return errorf(slice.Pos, "bit-slice [%d:%d] applied to a field with unknown width", slice.SliceLo, slice.SliceHi)
	}
	if int(slice.SliceHi) > width {
		return errorf(slice.Pos, "bit-slice [%d:%d] exceeds field width bit<%d>", slice.SliceLo, slice.SliceHi, width)
	}
	bits := int(slice.SliceHi - slice.SliceLo)
	// Cap at 128 bits = the widest single field the spec models.
	// Within the [1, 128] band:
	//   - widths ≤ 64 ride the single-LDX cmp / arith path (with a
	//     post-load shift+mask for non-aligned sub-byte slices)
	//   - widths > 64 ride the F12 desugar (= AND/OR-chain of
	//     LDX-aligned sub-cmps); only available in cmp context, not
	//     arith binops
	if bits > 128 {
		return errorf(slice.Pos, "bit-slice [%d:%d] yields %d bits; the spec caps at bit<128>", slice.SliceLo, slice.SliceHi, bits)
	}
	// For widths > 64 the F12 desugar requires byte-aligned
	// endpoints — the multi-chunk split currently only steps in
	// 8-bit increments. Sub-byte slices wider than 64 would need
	// additional plumbing; reject up front.
	if bits > 64 && (slice.SliceLo%8 != 0 || slice.SliceHi%8 != 0) {
		return errorf(slice.Pos, "bit-slice [%d:%d] yields %d bits and is not byte-aligned; the > 64 desugar path requires byte-aligned endpoints", slice.SliceLo, slice.SliceHi, bits)
	}
	ref.Slice = &ir.FieldSlice{Lo: int(slice.SliceLo), Hi: int(slice.SliceHi)}
	return nil
}

// lintArithCondition is the F1 strict-arith pass. It walks both
// sides of the cmp and reports binops whose operand shapes almost
// certainly wrap at the field's natural width. The set is
// intentionally narrow — we want to flag the obvious traps
// (`field + field`, `field - field` with RHS ≥ LHS, `field *
// field`) without false-positiving on the everyday `tcp.dport + 1`
// pattern. Callers opt in via resolve.Options.StrictArithLint.
func lintArithCondition(c *ir.Condition) error {
	if c == nil {
		return nil
	}
	if err := lintArithExpr(c.ArithL); err != nil {
		return err
	}
	return lintArithExpr(c.ArithR)
}

func lintArithExpr(e *ir.ArithExpr) error {
	if e == nil || e.Kind != ast.ArithBinOp {
		return nil
	}
	if err := lintArithExpr(e.Left); err != nil {
		return err
	}
	if err := lintArithExpr(e.Right); err != nil {
		return err
	}
	leftIsField := e.Left != nil && e.Left.Kind == ast.ArithField
	rightIsField := e.Right != nil && e.Right.Kind == ast.ArithField
	switch e.Op {
	case ast.ArithAdd, ast.ArithMul:
		if leftIsField && rightIsField {
			return errArithOverflowSuspect(e.Pos, e.Op)
		}
	case ast.ArithSub:
		if leftIsField && rightIsField {
			lb := exprMaxFieldBits(e.Left)
			rb := exprMaxFieldBits(e.Right)
			if rb >= lb {
				return errArithUnderflowSuspect(e.Pos, lb, rb)
			}
		}
	}
	return nil
}
