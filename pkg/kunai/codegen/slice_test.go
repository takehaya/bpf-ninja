package codegen

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
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

func TestSubByteWindow(t *testing.T) {
	cases := []struct {
		name             string
		bitOff, width    int
		byteOff, loadLen int
		ok               bool
	}{
		// byte-clean fields are not our path.
		{"byte-aligned byte field", 8, 8, 0, 0, false},
		{"byte-aligned 2-byte field", 16, 16, 0, 0, false},
		// sub-byte starts / widths.
		{"ipv4.version", 0, 4, 0, 1, true},
		{"ipv4.ihl", 4, 4, 0, 1, true},
		{"ipv4.flags", 48, 3, 6, 1, true},
		{"ipv4.frag_offset", 51, 13, 6, 2, true},
		{"tcp.data_offset", 96, 4, 12, 1, true},
		{"tcp.flags", 103, 9, 12, 2, true},
		{"ipv6.traffic_class", 4, 8, 0, 2, true},
		// covering window wider than a single 8-byte LDX → not ours.
		{"too wide", 1, 64, 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			byteOff, loadLen, ok := subByteWindow(c.bitOff, c.width)
			if ok != c.ok || (ok && (byteOff != c.byteOff || loadLen != c.loadLen)) {
				t.Errorf("subByteWindow(%d,%d) = (%d,%d,%v), want (%d,%d,%v)",
					c.bitOff, c.width, byteOff, loadLen, ok, c.byteOff, c.loadLen, c.ok)
			}
		})
	}
}

// subByteFieldRef builds a FieldRef over a synthetic single-field spec
// whose field sits at the given header bit offset (padded by a leading
// filler field) so slicePostAdjust resolves the real geometry.
func subByteFieldRef(bitOff, width int) *ir.FieldRef {
	fields := []vocab.Field{}
	if bitOff > 0 {
		fields = append(fields, vocab.Field{Name: "_pad", Bits: bitOff})
	}
	fields = append(fields, vocab.Field{Name: "f", Bits: width})
	return &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "p", Fields: fields}},
		Field: &vocab.Field{Name: "f", Bits: width},
	}
}

func TestSlicePostAdjustSubByteField(t *testing.T) {
	cases := []struct {
		name          string
		bitOff, width int
		loadBytes     int
		shift         int
		mask          uint64
	}{
		{"ipv4.version", 0, 4, 1, 4, 0xf},
		{"ipv4.ihl", 4, 4, 1, 0, 0xf},
		{"ipv4.flags", 48, 3, 1, 5, 0x7},
		{"ipv4.frag_offset", 51, 13, 2, 0, 0x1fff},
		{"tcp.data_offset", 96, 4, 1, 4, 0xf},
		{"tcp.flags", 103, 9, 2, 0, 0x1ff},
		{"ipv6.traffic_class", 4, 8, 2, 4, 0xff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref := subByteFieldRef(c.bitOff, c.width)
			shift, mask := slicePostAdjust(ref, c.loadBytes)
			if shift != c.shift || mask != c.mask {
				t.Errorf("slicePostAdjust = (shift=%d, mask=%#x), want (shift=%d, mask=%#x)",
					shift, mask, c.shift, c.mask)
			}
		})
	}
}

// A byte-clean primary field (and an empty/aux ref) must stay a no-op
// so existing F1–F10 emit is unchanged.
func TestSlicePostAdjustByteCleanFieldNoOp(t *testing.T) {
	ref := subByteFieldRef(16, 16) // dport-like: byte-aligned, 2 bytes
	if shift, mask := slicePostAdjust(ref, 2); shift != 0 || mask != 0 {
		t.Errorf("byte-clean field: got (shift=%d, mask=%#x), want (0, 0)", shift, mask)
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

// TestSliceNineByteWindow pins the window of a slice of at most 64 bits
// whose bytes span 9: it is read as 8 bytes and the ninth, never slides,
// and composes in five instructions (four for exactly 64 bits). A wider
// slice over 9 bytes stays refused.
func TestSliceNineByteWindow(t *testing.T) {
	ref := func(lo, hi int) *ir.FieldRef {
		return &ir.FieldRef{
			Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
			Field: &vocab.Field{Name: "dst", Bits: 128},
			Slice: &ir.FieldSlice{Lo: lo, Hi: hi},
		}
	}
	for _, tc := range []struct {
		lo, hi, off, insns int
	}{
		{60, 124, 7, 4},
		{61, 124, 7, 5},
		{4, 68, 0, 4},
	} {
		r := ref(tc.lo, tc.hi)
		off, size, err := applySliceToOffset(r, 0, 16)
		if err != nil || off != tc.off || size != sliceSplitWindow || !sliceSplitsLoad(r) {
			t.Errorf("[%d:%d] window = (%d, %d, %v), split %v; want (%d, 9, nil), split", tc.lo, tc.hi, off, size, err, sliceSplitsLoad(r), tc.off)
		}
		if got := len(emitFieldValue(r, 8, asm.DWord)); got != tc.insns {
			t.Errorf("[%d:%d] composes in %d instructions, want %d", tc.lo, tc.hi, got, tc.insns)
		}
	}
	if _, _, err := applySliceToOffset(ref(0, 72), 0, 16); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("[0:72]: err = %v, want ErrNotImplemented", err)
	}
	if sliceSplitsLoad(ref(56, 120)) {
		t.Error("[56:120] is byte-aligned over 8 bytes, not split")
	}
}

func TestApplySliceToOffsetStaysInsideField(t *testing.T) {
	// [92:124] covers bytes 11..15 of the address; the 8-byte window
	// from byte 11 would end 3 bytes past the field, so it starts at
	// byte 8 and the shift keeps the slice's bits.
	ref := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "ipv6"}},
		Field: &vocab.Field{Name: "dst", Bits: 128},
		Slice: &ir.FieldSlice{Lo: 92, Hi: 124},
	}
	off, size, err := applySliceToOffset(ref, 0, 16)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if off != 8 || size != 8 {
		t.Errorf("window = (%d, %d), want (8, 8)", off, size)
	}
	if shift, mask := slicePostAdjust(ref, size); shift != 4 || mask != 0xffffffff {
		t.Errorf("shift, mask = %d, %#x; want 4, 0xffffffff", shift, mask)
	}
	// A field exactly as wide as the window slides to its start.
	seq := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "tcp"}},
		Field: &vocab.Field{Name: "seq", Bits: 32},
		Slice: &ir.FieldSlice{Lo: 12, Hi: 28},
	}
	if off, size, err := applySliceToOffset(seq, 0, 4); err != nil || off != 0 || size != 4 {
		t.Errorf("tcp.seq[12:28] window = (%d, %d, %v), want (0, 4, nil)", off, size, err)
	}
	if shift, mask := slicePostAdjust(seq, 4); shift != 4 || mask != 0xffff {
		t.Errorf("tcp.seq[12:28] shift, mask = %d, %#x; want 4, 0xffff", shift, mask)
	}
	// A field narrower than the window keeps the slice's first byte.
	narrow := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "eth"}},
		Field: &vocab.Field{Name: "src", Bits: 48},
		Slice: &ir.FieldSlice{Lo: 12, Hi: 44},
	}
	if off, size, err := applySliceToOffset(narrow, 0, 6); err != nil || off != 1 || size != 8 {
		t.Errorf("eth.src[12:44] window = (%d, %d, %v), want (1, 8, nil)", off, size, err)
	}
}

// bundledFieldRef returns a ref to proto.field in the bundled vocab with
// the slice [lo:hi].
func bundledFieldRef(t *testing.T, proto, field string, lo, hi int) *ir.FieldRef {
	t.Helper()
	v, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("dslvocab.Bundled: %v", err)
	}
	spec := v[proto]
	if spec == nil {
		t.Fatalf("no protocol %s", proto)
	}
	for i := range spec.Fields {
		if spec.Fields[i].Name == field {
			return &ir.FieldRef{Layer: &ir.LayerInstance{Spec: spec}, Field: &spec.Fields[i], Slice: &ir.FieldSlice{Lo: lo, Hi: hi}}
		}
	}
	t.Fatalf("no field %s.%s", proto, field)
	return nil
}

// TestUnalignedFieldSliceWindow pins the window and the post-load shift
// and mask of a slice of a field that starts off a byte boundary: the
// slice is the bit range [bitOff+lo, bitOff+hi) of the header, read
// through the smallest window covering it (spec keyBytes / loadRefOn).
func TestUnalignedFieldSliceWindow(t *testing.T) {
	for _, c := range []struct {
		proto, field string
		lo, hi       int
		off, bytes   int
		shift        int
		mask         uint64
	}{
		{"ipv6", "traffic_class", 0, 6, 0, 2, 6, 0x3f}, // DSCP, header bits 4..10
		{"ipv6", "traffic_class", 6, 8, 1, 1, 4, 0x3},  // ECN, bits 10..12
		{"ipv6", "traffic_class", 0, 4, 0, 1, 0, 0xf},  // bits 4..8
		{"ipv4", "ihl", 2, 4, 0, 1, 0, 0x3},
		{"ipv6", "flow_label", 0, 8, 1, 2, 4, 0xff},   // bits 12..20
		{"ipv6", "flow_label", 8, 20, 2, 2, 0, 0xfff}, // bits 20..32
		{"ipv4", "frag_offset", 5, 13, 7, 1, 0, 0},    // fills its byte: no narrowing
		{"tcp", "flags", 1, 9, 13, 1, 0, 0},           // the tcp[13] byte, no narrowing
	} {
		ref := bundledFieldRef(t, c.proto, c.field, c.lo, c.hi)
		off, n, err := fieldRefByteOffset(ref)
		if err != nil {
			t.Errorf("%s.%s[%d:%d]: %v", c.proto, c.field, c.lo, c.hi, err)
			continue
		}
		shift, mask := slicePostAdjust(ref, n)
		if off != c.off || n != c.bytes || shift != c.shift || mask != c.mask {
			t.Errorf("%s.%s[%d:%d] = (off %d, %d bytes, shift %d, mask %#x), want (%d, %d, %d, %#x)",
				c.proto, c.field, c.lo, c.hi, off, n, shift, mask, c.off, c.bytes, c.shift, c.mask)
		}
	}
}

// TestUnalignedFieldSliceWindowsFitHeader: every slice of at most 64 bits
// of a bundled primary field that starts off a byte boundary resolves,
// and its window stays inside the fixed header. An unaligned field is
// read from its byte floor with no move-back, so a vocab field near a
// header's end would read past it; this fails loudly if one appears.
func TestUnalignedFieldSliceWindowsFitHeader(t *testing.T) {
	v, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("dslvocab.Bundled: %v", err)
	}
	for _, spec := range v {
		hdr, err := headerSize(spec)
		if err != nil {
			continue
		}
		for i := range spec.Fields {
			f := &spec.Fields[i]
			bitOff, _, _ := vocab.BitOffsetIn(spec.Fields, f.Name)
			if bitOff%8 == 0 {
				continue
			}
			for lo := 0; lo < f.Bits; lo++ {
				for hi := lo + 1; hi <= f.Bits && hi-lo <= 64; hi++ {
					ref := &ir.FieldRef{Layer: &ir.LayerInstance{Spec: spec}, Field: f, Slice: &ir.FieldSlice{Lo: lo, Hi: hi}}
					off, n, err := fieldRefByteOffset(ref)
					if err != nil {
						t.Errorf("%s.%s[%d:%d]: %v", spec.Name, f.Name, lo, hi, err)
						continue
					}
					if off+n > hdr {
						t.Errorf("%s.%s[%d:%d]: window %d..%d runs past the %d-byte header", spec.Name, f.Name, lo, hi, off, off+n, hdr)
					}
				}
			}
		}
	}
}
