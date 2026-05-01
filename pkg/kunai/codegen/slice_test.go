package codegen

import (
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// Unit tests for the bit-slice arithmetic helpers in codegen.go.
// These compute load offsets and post-load shift / mask values
// from a FieldRef.Slice; getting them wrong silently produces
// wrong cmp results in the field, so pin the math here rather
// than rely on packet-level tests.

func TestNextLDXSize(t *testing.T) {
	cases := []struct {
		cover int
		want  int
	}{
		{0, 1}, // edge: zero rounds up to the smallest LDX
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{9, 0}, // exceeds single-LDX cap
		{16, 0},
	}
	for _, c := range cases {
		got := nextLDXSize(c.cover)
		if got != c.want {
			t.Errorf("nextLDXSize(%d) = %d, want %d", c.cover, got, c.want)
		}
	}
}

func TestSlicePostAdjustNoSlice(t *testing.T) {
	ref := &ir.FieldRef{}
	shift, mask := slicePostAdjust(ref, 4)
	if shift != 0 || mask != 0 {
		t.Errorf("nil slice: got (shift=%d, mask=%#x), want (0, 0)", shift, mask)
	}
}

func TestSlicePostAdjustAlignedFullLoad(t *testing.T) {
	// A slice that exactly fills the load (e.g. [0:32] with a
	// 4-byte load) needs no post-adjust.
	ref := &ir.FieldRef{Slice: &ir.FieldSlice{Lo: 0, Hi: 32}}
	shift, mask := slicePostAdjust(ref, 4)
	if shift != 0 || mask != 0 {
		t.Errorf("[0:32] over 4-byte load: got (shift=%d, mask=%#x), want (0, 0)", shift, mask)
	}
}

func TestSlicePostAdjustNonAligned(t *testing.T) {
	cases := []struct {
		name      string
		slice     ir.FieldSlice
		loadBytes int
		shift     int
		mask      uint64
	}{
		{
			// `[3:9]` over a 2-byte load (= 16 bits cover).
			// Width = 6. shift = 16 - 9 = 7. mask = 0x3f.
			name:      "[3:9] in 2-byte load",
			slice:     ir.FieldSlice{Lo: 3, Hi: 9},
			loadBytes: 2,
			shift:     7,
			mask:      0x3f,
		},
		{
			// `[4:12]` over a 2-byte load. Width = 8.
			// shift = 16 - 12 = 4. mask = 0xff.
			name:      "[4:12] in 2-byte load",
			slice:     ir.FieldSlice{Lo: 4, Hi: 12},
			loadBytes: 2,
			shift:     4,
			mask:      0xff,
		},
		{
			// `[0:24]` over a 4-byte load (cover 3 → 4). Width = 24.
			// shift = 32 - 24 = 8. mask = 0xff_ff_ff.
			name:      "[0:24] in 4-byte load",
			slice:     ir.FieldSlice{Lo: 0, Hi: 24},
			loadBytes: 4,
			shift:     8,
			mask:      0xffffff,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref := &ir.FieldRef{Slice: &c.slice}
			shift, mask := slicePostAdjust(ref, c.loadBytes)
			if shift != c.shift {
				t.Errorf("shift = %d, want %d", shift, c.shift)
			}
			if mask != c.mask {
				t.Errorf("mask = %#x, want %#x", mask, c.mask)
			}
		})
	}
}

func TestApplySliceToOffsetByteAligned(t *testing.T) {
	// Byte-aligned slice on a 16-byte field narrows (off, size).
	ref := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
		Slice: &ir.FieldSlice{Lo: 64, Hi: 96},
	}
	off, size, err := applySliceToOffset(ref, 0, 16)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if off != 8 {
		t.Errorf("off = %d, want 8 (= byte 8 of the 128-bit field)", off)
	}
	if size != 4 {
		t.Errorf("size = %d, want 4 (= 32 bits)", size)
	}
}

func TestApplySliceToOffsetNonAlignedRoundsUp(t *testing.T) {
	// Sub-byte slice rounds the load size up to next pow2.
	ref := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
		Slice: &ir.FieldSlice{Lo: 3, Hi: 9},
	}
	off, size, err := applySliceToOffset(ref, 0, 16)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if off != 0 {
		t.Errorf("off = %d, want 0 (slice starts in byte 0)", off)
	}
	// cover = ceil(9/8) - floor(3/8) = 2 - 0 = 2. Next pow2 = 2.
	if size != 2 {
		t.Errorf("size = %d, want 2", size)
	}
}

func TestApplySliceToOffsetCoverTooLarge(t *testing.T) {
	// A slice whose cover bytes > 8 can't fit in a single LDX —
	// surface ErrNotImplemented via the helper.
	ref := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "src", Bits: 128},
		Slice: &ir.FieldSlice{Lo: 0, Hi: 96}, // 12 bytes; > 8
	}
	_, _, err := applySliceToOffset(ref, 0, 16)
	if err == nil {
		t.Fatal("expected error for 12-byte cover (max 8)")
	}
}
