package resolve

import (
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// Unit tests for the helpers in typing.go that don't need vocab /
// resolver state — they compute fixed mappings (slice -> chunks,
// arith tree -> max bits, etc.) and the rest of the codegen
// depends on them being arithmetically correct.

func TestSplitSliceIntoLDXChunks(t *testing.T) {
	cases := []struct {
		width int
		want  []chunk
	}{
		// Greedy descending: 8 → 4 → 2 → 1 byte chunks. Sub-LDX
		// widths get split rather than padded to the next pow2,
		// because each chunk becomes its own cmp emit downstream.
		{8, []chunk{{0, 8}}},
		{16, []chunk{{0, 16}}},
		{24, []chunk{{0, 16}, {16, 24}}}, // 2 + 1
		{32, []chunk{{0, 32}}},
		{56, []chunk{{0, 32}, {32, 48}, {48, 56}}}, // 4 + 2 + 1
		{64, []chunk{{0, 64}}},
		{72, []chunk{{0, 64}, {64, 72}}},        // 8 + 1 byte
		{80, []chunk{{0, 64}, {64, 80}}},        // 8 + 2
		{88, []chunk{{0, 64}, {64, 80}, {80, 88}}}, // 8 + 2 + 1
		{96, []chunk{{0, 64}, {64, 96}}},        // 8 + 4
		{104, []chunk{{0, 64}, {64, 96}, {96, 104}}},
		{112, []chunk{{0, 64}, {64, 96}, {96, 112}}},
		{120, []chunk{{0, 64}, {64, 96}, {96, 112}, {112, 120}}},
		{128, []chunk{{0, 64}, {64, 128}}},
	}
	for _, c := range cases {
		got := splitSliceIntoLDXChunks(c.width)
		if !chunksEqual(got, c.want) {
			t.Errorf("splitSliceIntoLDXChunks(%d) = %v, want %v", c.width, got, c.want)
		}
	}
}

func chunksEqual(a, b []chunk) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestUintFitsBits(t *testing.T) {
	cases := []struct {
		v    uint64
		bits int
		ok   bool
	}{
		// Positive values within the unsigned range.
		{0, 8, true},
		{255, 8, true},
		{256, 8, false},
		{443, 16, true},
		{99999, 16, false},
		// Negative literals stored as 2's complement.
		{^uint64(0), 8, true},          // -1 fits any width
		{^uint64(0), 16, true},
		{^uint64(127), 8, true},        // -128 fits int8 range
		{^uint64(128), 8, false},       // -129 doesn't fit signed int8
		{^uint64(128), 16, true},       // -129 fits int16
		{^uint64(32767), 16, true},     // -32768 fits int16
		{^uint64(32768), 16, false},    // -32769 doesn't
		// 64-bit and wider always succeed (no narrowing happens).
		{^uint64(0), 64, true},
	}
	for _, c := range cases {
		got := uintFitsBits(c.v, c.bits)
		if got != c.ok {
			t.Errorf("uintFitsBits(%#x, %d) = %v, want %v", c.v, c.bits, got, c.ok)
		}
	}
}

func TestArithMaxFieldBitsRespectsSlice(t *testing.T) {
	// The slice-aware EffectiveBits() reading is what makes the
	// 128-bit cmp pipeline route correctly when slices are in
	// play. Pin both the un-sliced and sliced paths.
	field128 := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
	}
	exprFull := &ir.ArithExpr{Kind: ast.ArithField, Field: field128}
	if got := exprMaxFieldBits(exprFull); got != 128 {
		t.Errorf("full Int<128> field: got %d, want 128", got)
	}

	field128Sliced := *field128
	field128Sliced.Slice = &ir.FieldSlice{Lo: 0, Hi: 32}
	exprSlice := &ir.ArithExpr{Kind: ast.ArithField, Field: &field128Sliced}
	if got := exprMaxFieldBits(exprSlice); got != 32 {
		t.Errorf("Int<128>[0:32] slice: got %d, want 32", got)
	}
}

func TestTryDesugarMultiLDXSliceCmpStructure(t *testing.T) {
	// 96-bit slice cmp must desugar into WAnd of WAtomArith[0:64]
	// and WAtomArith[64:96]. Sanity-check the resulting tree shape
	// so a future refactor can't silently regress the desugar.
	field := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
	}
	lhsRef := *field
	lhsRef.Slice = &ir.FieldSlice{Lo: 0, Hi: 96}
	rhsField := *field
	rhsField.Field = &vocab.Field{Name: "dst", Bits: 128}
	rhsRef := rhsField
	rhsRef.Slice = &ir.FieldSlice{Lo: 0, Hi: 96}

	al := &ir.ArithExpr{Kind: ast.ArithField, Field: &lhsRef}
	ar := &ir.ArithExpr{Kind: ast.ArithField, Field: &rhsRef}
	got := tryDesugarMultiLDXSliceCmp(al, ar, ast.CmpEq, ast.Position{})
	if got == nil {
		t.Fatal("desugar returned nil for 96-bit slice cmp")
	}
	if got.Kind != ast.WAnd {
		t.Fatalf("top kind = %v, want WAnd", got.Kind)
	}
	// Left = WAtomArith on [0:64], Right = WAtomArith on [64:96].
	if got.Left == nil || got.Left.Kind != ast.WAtomArith {
		t.Fatalf("Left = %+v, want WAtomArith", got.Left)
	}
	if got.Right == nil || got.Right.Kind != ast.WAtomArith {
		t.Fatalf("Right = %+v, want WAtomArith", got.Right)
	}
	if leftSlice := got.Left.ArithL.Field.Slice; leftSlice == nil || leftSlice.Lo != 0 || leftSlice.Hi != 64 {
		t.Errorf("left LHS slice = %+v, want [0:64]", leftSlice)
	}
	if rightSlice := got.Right.ArithL.Field.Slice; rightSlice == nil || rightSlice.Lo != 64 || rightSlice.Hi != 96 {
		t.Errorf("right LHS slice = %+v, want [64:96]", rightSlice)
	}
}

func TestTryDesugarMultiLDXSliceCmpReturnsNilForNonMatch(t *testing.T) {
	// Patterns that should *not* trigger desugar: width ≤ 64, op
	// not ==/!=, mismatched widths, non-slice operand, etc.
	field := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
	}
	makeSlice := func(lo, hi int) *ir.ArithExpr {
		ref := *field
		ref.Slice = &ir.FieldSlice{Lo: lo, Hi: hi}
		return &ir.ArithExpr{Kind: ast.ArithField, Field: &ref}
	}
	cases := []struct {
		name string
		al   *ir.ArithExpr
		ar   *ir.ArithExpr
		op   ast.CmpOp
	}{
		{"width-le-64", makeSlice(0, 64), makeSlice(0, 64), ast.CmpEq},
		{"ordered-cmp", makeSlice(0, 96), makeSlice(0, 96), ast.CmpLt},
		{"mismatched-widths", makeSlice(0, 96), makeSlice(0, 80), ast.CmpEq},
		{"no-slice", &ir.ArithExpr{Kind: ast.ArithField, Field: field}, makeSlice(0, 96), ast.CmpEq},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tryDesugarMultiLDXSliceCmp(c.al, c.ar, c.op, ast.Position{}); got != nil {
				t.Errorf("expected nil, got %+v", got)
			}
		})
	}
}

func TestAttachSliceValidation(t *testing.T) {
	field := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
	}
	cases := []struct {
		name        string
		idx         *ast.IndexExpr
		wantError   string
	}{
		{"exceeds-128", &ast.IndexExpr{IsSlice: true, SliceLo: 0, SliceHi: 200}, "exceeds field width"},
		{"width-over-128", &ast.IndexExpr{IsSlice: true, SliceLo: 0, SliceHi: 129}, "exceeds field width"},
		{"non-aligned-wide", &ast.IndexExpr{IsSlice: true, SliceLo: 1, SliceHi: 100}, "not byte-aligned"},
		{"valid-byte-aligned", &ast.IndexExpr{IsSlice: true, SliceLo: 0, SliceHi: 64}, ""},
		{"valid-non-aligned-narrow", &ast.IndexExpr{IsSlice: true, SliceLo: 3, SliceHi: 9}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref := *field
			err := attachSlice(&ref, c.idx)
			if c.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if ref.Slice == nil {
					t.Error("expected Slice to be set")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", c.wantError)
			}
			if !contains(err.Error(), c.wantError) {
				t.Errorf("err = %v; want substring %q", err, c.wantError)
			}
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
