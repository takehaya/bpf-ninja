package record

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

// CheckBlock validates a block's header against the layout.
func (l *Layout) CheckBlock(b []byte) error {
	if len(b) < HeaderSize {
		return fmt.Errorf("record block too short: %d bytes", len(b))
	}
	if n := int(binary.NativeEndian.Uint16(b[OffLen:])); n != len(b) || n != l.Size() {
		return fmt.Errorf("record block length %d, layout %d, have %d", n, l.Size(), len(b))
	}
	if b[OffVersion] != BlockVersion || b[OffKind] != l.Kind() {
		return fmt.Errorf("record block version %d kind %d does not match the layout", b[OffVersion], b[OffKind])
	}
	if l.Mode == ModeEntry {
		k := binary.NativeEndian.Uint16(b[EntryOffKeyLen:])
		v := binary.NativeEndian.Uint16(b[EntryOffValueLen:])
		if uint32(k) != l.Key.Len || uint32(v) != l.Value.Len {
			return fmt.Errorf("record block key/value lengths %d/%d do not match the layout", k, v)
		}
	}
	return nil
}

// Comment renders a block as space-separated NAME=VALUE pairs. Names use
// --arg-filter expression syntax (value->action, key->dport, value[0]); a
// field whose read failed shows "?". Integers are decimal, signed ones
// sign-extended, except an entry block's status and info, which are 0x%016x so
// their halves stay readable; byte arrays and unions are hex. Pointers stored inside a
// key or value are not rendered.
func (l *Layout) Comment(b []byte) (string, error) {
	c, err := l.AppendComment(nil, b)
	return string(c), err
}

// commentBuf builds a space-separated comment into a reusable byte slice.
// Values are appended in place; only a member path through a nested struct,
// or one longer than 32 bytes, allocates.
type commentBuf struct{ b []byte }

func (c *commentBuf) sep() {
	if len(c.b) > 0 {
		c.b = append(c.b, ' ')
	}
}
func (c *commentBuf) raw(name, rest string) { c.sep(); c.b = append(append(c.b, name...), rest...) }
func (c *commentBuf) uint(name string, v uint64) {
	c.sep()
	c.b = strconv.AppendUint(append(append(c.b, name...), '='), v, 10)
}
func (c *commentBuf) int(name string, v int64) {
	c.sep()
	c.b = strconv.AppendInt(append(append(c.b, name...), '='), v, 10)
}

// word emits name=0x%016x, so the halves of a status word
// ((u32)ret | flags << 32) or an info word stay readable.
func (c *commentBuf) word(name string, v uint64) {
	c.sep()
	c.b = append(append(c.b, name...), "=0x"...)
	for shift := 60; shift >= 0; shift -= 4 {
		c.b = append(c.b, "0123456789abcdef"[v>>uint(shift)&0xf])
	}
}
func (c *commentBuf) hex(name string, data []byte) {
	c.sep()
	c.b = hex.AppendEncode(append(append(c.b, name...), '='), data)
}

// bytesMarker emits NAME_bytes=len/size, noting a field cut to len of size.
func (c *commentBuf) bytesMarker(name string, length, size uint32) {
	c.sep()
	c.b = append(c.b, name...)
	c.b = append(c.b, "_bytes="...)
	c.b = strconv.AppendUint(c.b, uint64(length), 10)
	c.b = append(c.b, '/')
	c.b = strconv.AppendUint(c.b, uint64(size), 10)
}

// AppendComment renders the block onto dst and returns the extended slice,
// so a caller can reuse one buffer across packets.
func (l *Layout) AppendComment(dst []byte, b []byte) ([]byte, error) {
	if err := l.CheckBlock(b); err != nil {
		return dst, err
	}
	valid := binary.NativeEndian.Uint32(b[OffValid:])
	c := &commentBuf{b: dst}
	if l.Mode == ModeFilter {
		for i, f := range l.Fields {
			v := binary.NativeEndian.Uint64(b[HeaderSize+8*i:])
			switch {
			case valid&(1<<i) == 0:
				c.raw(f.Name, "=?")
			case f.Pointer && v == 0:
				c.raw(f.Name, "=null")
			case f.Pointer:
				c.raw(f.Name, "!=null")
			case f.Signed:
				c.int(f.Name, int64(v))
			default:
				c.uint(f.Name, v)
			}
		}
		return c.b, nil
	}
	scalar := func(s Scalar, bit uint32, v uint64, word bool) {
		if !s.Present() {
			return
		}
		name := s.Name
		if s.Name == "info" && s.Size == 4 {
			name = "site"
		}
		switch {
		case valid&bit == 0:
			c.raw(name, "=?")
		case word:
			c.word(name, v)
		default:
			c.uint(name, v)
		}
	}
	scalar(l.Site, ValidSite, uint64(binary.NativeEndian.Uint32(b[EntryOffSite:])), false)
	scalar(l.Status, ValidStatus, binary.NativeEndian.Uint64(b[EntryOffStatus:]), true)
	off := EntryOffBytes
	for _, e := range []struct {
		bytes Bytes
		bit   uint32
	}{{l.Key, ValidKey}, {l.Value, ValidValue}} {
		v := e.bytes
		data := b[off : off+int(v.Len)]
		off += int(v.Len)
		if !v.Present() {
			continue
		}
		if v.Len == 0 {
			// A field capped to zero bytes still reports that it was cut, so
			// --record-max 0 keeps a marker (an untyped value with no size tag
			// has Size 0 and records nothing).
			if v.Size > 0 {
				c.bytesMarker(v.Name, 0, v.Size)
			}
			continue
		}
		if valid&e.bit == 0 {
			c.raw(v.Name, "=?")
			continue
		}
		renderBytes(c, v, data)
		if v.Len < v.Size {
			c.bytesMarker(v.Name, v.Len, v.Size)
		}
	}
	return c.b, nil
}

// renderBytes decodes a key or value with memberSink.show, which fails
// closed: only plain data (hookabi.Plain) is shown, so no pointer-typed or
// bpf_* field reaches a comment (an address kept in a plain integer cannot
// be told apart from any other integer).
func renderBytes(c *commentBuf, v Bytes, data []byte) {
	s := memberSink{c: c, data: data}
	s.show(v, len(data))
}

// memberSink renders the members walk visits into c, or with c nil only
// adds up their worst-case comment length in n.
type memberSink struct {
	c     *commentBuf
	data  []byte
	n     int
	shape *[]memberShape
}

type memberShape struct {
	name             string
	off, bits, width uint32
	size             int
	signed, boolean  bool
}

// show visits what a comment shows of key or value v from its first n
// recorded bytes. The renderer and MaxCommentLen both use it, with one rule
// for every top-level shape:
//   - an integer argument (not a pointer): NAME=decimal;
//   - untyped bytes (no BTF type, void, or the struct { u8 bytes[N]; } a
//     typed hook gets for a map side without BTF): NAME=hex of the recorded
//     bytes;
//   - a struct: its members (walk), except that an Opaque struct shows
//     nothing;
//   - an integer or enum: NAME[0]=decimal when all of it is recorded;
//   - a plain array or union: NAME=hex of the recorded bytes;
//   - anything else (a pointer, a non-plain array or union) shows nothing.
func (s *memberSink) show(v Bytes, n int) {
	if n == 0 {
		return
	}
	if !v.Pointer {
		if s.c == nil {
			s.n += 1 + len(v.Name) + 1 + maxUintDigits
		} else {
			s.c.uint(v.Name, readUint(s.data[:n]))
		}
		return
	}
	var t btf.Type
	if v.Type != nil {
		t = btf.UnderlyingType(v.Type)
	}
	switch t := t.(type) {
	case nil, *btf.Void:
		s.visit(v.Name, nil, 0, 0, n)
	case *btf.Struct:
		switch {
		case rawBytes(t):
			s.visit(v.Name, nil, 0, 0, n)
		case !hookabi.Opaque(t):
			s.walk(v.Name+"->", t.Members, 0, n)
		}
	case *btf.Int, *btf.Enum:
		if size, ok := scalarSpan(t, 0, 0); ok && int(size) <= n {
			s.visit(v.Name+"[0]", t, 0, 0, int(size))
		}
	case *btf.Array, *btf.Union:
		if hookabi.Plain(t) {
			s.visit(v.Name, t, 0, 0, n)
		}
	}
}

// rawBytes reports whether t is the struct { u8 bytes[N]; } inject-run
// passes a typed hook for a map side without BTF, so it is spelled like the
// untyped bytes an untrusted hook records.
func rawBytes(t *btf.Struct) bool {
	if t.Name != "" || len(t.Members) != 1 || t.Members[0].Name != "bytes" {
		return false
	}
	a, ok := btf.UnderlyingType(t.Members[0].Type).(*btf.Array)
	if !ok {
		return false
	}
	i, ok := btf.UnderlyingType(a.Type).(*btf.Int)
	return ok && i.Size == 1
}

// walk visits, in order, each member a comment shows that lies in the first
// n recorded bytes: an integer or enum (size is the bytes it spans) or a
// plain array or named union (size is its byte size, shown as hex). It fails
// closed (hookabi.Plain): pointers, bpf_* structs, and arrays or unions
// holding either are skipped, while any other struct is walked so its plain
// members still show. Anonymous structs and plain anonymous unions are
// flattened under the --arg-filter names. The renderer and MaxCommentLen
// share it, so the bound covers exactly what is rendered.
func (s *memberSink) walk(prefix string, members []btf.Member, base uint32, n int) {
	for _, m := range members {
		off := base + uint32(m.Offset)
		name := prefix + m.Name
		switch t := btf.UnderlyingType(m.Type).(type) {
		case *btf.Struct:
			if hookabi.Opaque(t) {
				continue
			}
			p := name + "."
			if m.Name == "" {
				p = prefix
			}
			s.walk(p, t.Members, off, n)
		case *btf.Int, *btf.Enum:
			bits := uint32(m.BitfieldSize)
			if size, ok := scalarSpan(t, off%8, bits); ok && int(off/8+size) <= n {
				s.visit(name, t, off, bits, int(size))
			}
		case *btf.Union, *btf.Array:
			if !hookabi.Plain(t) {
				continue // a pointer array / union with a pointer is skipped
			}
			if u, ok := t.(*btf.Union); ok && m.Name == "" {
				s.walk(prefix, u.Members, off, n)
				continue
			}
			// A zero-size member (a flexible array such as data[]) has nothing to show.
			if size, err := btf.Sizeof(t); err == nil && size > 0 && off%8 == 0 && int(off/8)+size <= n {
				s.visit(name, t, off, 0, size)
			}
		}
		// Pointers and anything else are not decision state: skip.
	}
}

func (s *memberSink) visit(name string, t btf.Type, off, bits uint32, size int) {
	if s.shape != nil {
		shape := memberShape{name: name, off: off, bits: bits, size: size}
		switch t := t.(type) {
		case *btf.Int:
			shape.width, shape.signed, shape.boolean = t.Size*8, t.Encoding == btf.Signed, t.Encoding == btf.Bool
		case *btf.Enum:
			shape.width, shape.signed = t.Size*8, t.Signed
		}
		if bits > 0 {
			shape.width = bits
		}
		*s.shape = append(*s.shape, shape)
		return
	}
	switch {
	case s.c == nil && isScalar(t):
		s.n += 1 + len(name) + 1 + maxUintDigits
	case s.c == nil:
		s.n += 1 + len(name) + 1 + 2*size
	case isScalar(t):
		s.c.scalar(name, t, s.data, off/8, off%8, bits)
	default:
		s.c.hex(name, s.data[off/8:int(off/8)+size])
	}
}

func commentShape(v Bytes) []memberShape {
	var shape []memberShape
	(&memberSink{shape: &shape}).show(v, int(v.Len))
	return shape
}

func isScalar(t btf.Type) bool {
	switch t.(type) {
	case *btf.Int, *btf.Enum:
		return true
	}
	return false
}

// scalar emits name=VALUE for the integer or enum at byte off (plus bit for
// a bitfield of bits width), and nothing when it lies past the recorded
// bytes.
func (c *commentBuf) scalar(name string, t btf.Type, data []byte, off, bit, bits uint32) {
	n := len(c.b)
	c.sep()
	var ok bool
	if c.b, ok = appendScalar(append(append(c.b, name...), '='), t, data, off, bit, bits); !ok {
		c.b = c.b[:n]
	}
}

// scalarSpan is the bytes an integer or enum (a bitfield of bits width at
// bit, when bits > 0) spans, or false for anything else.
func scalarSpan(t btf.Type, bit, bits uint32) (uint32, bool) {
	var size uint32
	switch s := t.(type) {
	case *btf.Int:
		size = s.Size
	case *btf.Enum:
		size = s.Size
	default:
		return 0, false
	}
	if bits > 0 {
		// A bitfield needs only the bytes its bits occupy.
		size = (bit + bits + 7) / 8
	}
	return size, size > 0 && size <= 8
}

func appendScalar(dst []byte, t btf.Type, data []byte, off, bit, bits uint32) ([]byte, bool) {
	size, ok := scalarSpan(t, bit, bits)
	if !ok || int(off+size) > len(data) {
		return dst, false
	}
	var signed, boolean bool
	width := size * 8
	switch s := t.(type) {
	case *btf.Int:
		signed, boolean, width = s.Encoding == btf.Signed, s.Encoding == btf.Bool, s.Size*8
	case *btf.Enum:
		signed, width = s.Signed, s.Size*8
	}
	if bits > 0 {
		width = bits
	}
	v := readUint(data[off : off+size])
	if bits > 0 {
		v = v >> bit & (1<<bits - 1)
	}
	if boolean {
		return strconv.AppendBool(dst, v != 0), true
	}
	if signed && width < 64 {
		shift := 64 - width
		return strconv.AppendInt(dst, int64(v<<shift)>>shift, 10), true
	}
	if signed {
		return strconv.AppendInt(dst, int64(v), 10), true
	}
	return strconv.AppendUint(dst, v, 10), true
}

func readUint(b []byte) uint64 {
	var buf [8]byte
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		copy(buf[:], b)
		return binary.LittleEndian.Uint64(buf[:])
	}
	copy(buf[8-len(b):], b)
	return binary.BigEndian.Uint64(buf[:])
}

// maxUintDigits is the widest decimal rendering of a u64.
const maxUintDigits = 20

// ReturnPrefixLen is the room the writer's exit-mode "return=0x%08x "
// prefix takes ahead of a comment.
const ReturnPrefixLen = len("return=0x00000000 ")

// MaxCommentLen is an upper bound on the comment Comment produces for any
// block of this layout, so a caller can reject a layout whose worst-case
// comment would not fit a pcapng option (65535 bytes) before capturing. It
// counts only the bytes the layout records (Bytes.Len).
func (l *Layout) MaxCommentLen() int {
	n := 0
	add := func(extra int) {
		if n > 0 {
			n++ // separator
		}
		n += extra
	}
	if l.Mode == ModeFilter {
		for _, f := range l.Fields {
			add(len(f.Name) + 1 + maxUintDigits) // name= + value / !=null (shorter)
		}
		return n
	}
	if l.Site.Present() {
		add(len("site") + 1 + maxUintDigits)
	}
	if l.Status.Present() {
		add(len(l.Status.Name) + len("=0x") + 16)
	}
	for _, v := range []Bytes{l.Key, l.Value} {
		if !v.Present() {
			continue
		}
		// A failed read still writes NAME=?.
		var s memberSink
		s.show(v, int(v.Len))
		add(max(s.n, len(v.Name)+len("=?")))
		if v.Len < v.Size {
			add(len(v.Name) + len("_bytes=") + 2*maxUintDigits + 1)
		}
	}
	return n
}

// SameComment reports whether a block written with layout b renders, read
// with layout a, the comment b would give it. A capture decodes every
// record of one site with the site's first layout, so a later program that
// joins the site needs a layout this holds for. Argument positions and read
// offsets may differ: they only say where the BPF side finds the values.
// Two nil layouts (nothing recorded) are the same; a nil and a non-nil are
// not.
func SameComment(a, b *Layout) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Mode != b.Mode || a.Size() != b.Size() {
		return false
	}
	if a.Mode == ModeFilter {
		for i, f := range a.Fields { // equal sizes mean equal field counts
			if g := b.Fields[i]; f.Name != g.Name || f.Pointer != g.Pointer || f.Signed != g.Signed {
				return false
			}
		}
		return true
	}
	sameScalar := func(x, y Scalar) bool {
		return x.Present() == y.Present() && (!x.Present() || x.Name == y.Name && x.Size == y.Size)
	}
	sameBytes := func(x, y Bytes) bool {
		return x.Present() == y.Present() && x.Len == y.Len &&
			(!x.Present() || x.Name == y.Name && x.Pointer == y.Pointer && x.Size == y.Size)
	}
	if !sameScalar(a.Site, b.Site) || !sameScalar(a.Status, b.Status) || !sameBytes(a.Key, b.Key) || !sameBytes(a.Value, b.Value) {
		return false
	}
	return slices.Equal(commentShape(a.Key), commentShape(b.Key)) &&
		slices.Equal(commentShape(a.Value), commentShape(b.Value))
}
