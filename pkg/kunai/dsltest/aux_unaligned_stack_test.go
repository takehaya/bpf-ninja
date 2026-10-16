package dsltest

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// loadUnalignedStackVocab is eth plus a protocol `bar` with a counted
// stack of 8-byte entries whose field x is 17 bits at bit 9 (bytes 1..4,
// read through a 4-byte window) and whose field y is 17 bits at bit 47
// (its 4-byte window would run past the entry). The geneve OVN option
// is the only bundled aux field off a byte boundary, and it is read off
// an option slot; this fixture reaches the static-entry, runtime-index
// and any()/all() readers. `baz` (below) carries a 64-bit field at bit 1
// of 16-byte entries.
var loadUnalignedStackVocab = sync.OnceValues(func() (map[string]*vocab.ProtocolSpec, error) {
	const ethSrc = `
header eth_h { bit<48> dst; bit<48> src; bit<16> ethertype; }
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	const barSrc = `
header bar_h { bit<8> count; bit<8> idx; bit<16> tag; }
header bar_e { bit<8> a; bit<1> r; bit<17> x; bit<20> pad; bit<1> q; bit<17> y; }
const bit<16> KUNAI_BAR_ETH_ETHERTYPE = 0x88b6;
extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}
@kunai_option_region[on_fault=fail]
parser BarParser(packet_in pkt, out bar_h hdr, out bar_e[4] entries) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set((bit<8>)(hdr.count + 0));
        transition walk;
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume;
        }
    }
    state consume {
        pkt.extract(entries.next);
        pc.decrement(1);
        transition walk;
    }
}
`
	// baz has 16-byte entries: w is 64 bits at bit 1 (a [0:64] slice
	// straddles 9 bytes), a is a byte-aligned 32-bit field.
	const bazSrc = `
header baz_h { bit<8> count; bit<8> idx; bit<16> tag; }
header baz_e { bit<1> r; bit<64> w; bit<7> pad; bit<32> a; bit<24> pad2; }
const bit<16> KUNAI_BAZ_ETH_ETHERTYPE = 0x88b7;
extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}
@kunai_option_region[on_fault=fail]
parser BazParser(packet_in pkt, out baz_h hdr, out baz_e[4] entries) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set((bit<8>)(hdr.count + 0));
        transition walk;
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume;
        }
    }
    state consume {
        pkt.extract(entries.next);
        pc.decrement(1);
        transition walk;
    }
}
`
	return vocab.Load(fstest.MapFS{
		"vocab/eth.p4": &fstest.MapFile{Data: []byte(ethSrc)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(barSrc)},
		"vocab/baz.p4": &fstest.MapFile{Data: []byte(bazSrc)},
	}, "vocab")
})

// barEntry packs one 8-byte entry: a, then r(1) x(17) pad(20) q(1) y(17)
// big-endian, with the neighbours of x set so a missing mask shows.
func barEntry(x uint32) []byte {
	v := uint64(0xff)<<56 | uint64(1)<<55 | uint64(x&0x1ffff)<<38 | uint64(0xfffff)<<18 | uint64(1)<<17 | 0x1ffff
	b := make([]byte, 8)
	for i := range b {
		b[i] = byte(v >> (56 - 8*i))
	}
	return b
}

func barFrame(idx byte, xs ...uint32) []byte {
	pkt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb6, byte(len(xs)), idx, 0, 0}
	for _, x := range xs {
		pkt = append(pkt, barEntry(x)...)
	}
	return append(pkt, 'a', 'a', 'a', 'a')
}

// TestAuxStackUnalignedField reads a 17-bit field at bit 9 of each stack
// entry through a static index, a runtime index, a bracket and any()/
// all(), and refuses a field whose window would leave the entry.
func TestAuxStackUnalignedField(t *testing.T) {
	specs, err := loadUnalignedStackVocab()
	if err != nil {
		t.Fatalf("vocab: %v", err)
	}
	for _, tc := range []struct {
		expr          string
		match, reject [][]byte
	}{
		{"eth/bar where bar.entries[1].x == 0x1abcd",
			[][]byte{barFrame(0, 0, 0x1abcd)}, [][]byte{barFrame(0, 0x1abcd, 0), barFrame(0, 0x1abcd)}},
		{"eth/bar[entries[1].x == 0x1abcd]",
			[][]byte{barFrame(0, 0, 0x1abcd)}, [][]byte{barFrame(0, 0x1abcd, 0)}},
		{"eth/bar where bar.entries[bar.idx].x == 0x1abcd",
			[][]byte{barFrame(2, 0, 1, 0x1abcd), barFrame(0, 0x1abcd)}, [][]byte{barFrame(1, 0x1abcd, 0), barFrame(3, 0x1abcd, 0x1abcd, 0x1abcd)}},
		{"eth/bar where any(bar.entries.x == 0x1abcd)",
			[][]byte{barFrame(0, 1, 2, 0x1abcd, 3), barFrame(0, 0x1abcd)}, [][]byte{barFrame(0, 1, 2, 3, 0x1abcc), barFrame(0)}},
		{"eth/bar where all(bar.entries.x > 0x10000)",
			[][]byte{barFrame(0, 0x10001, 0x1ffff, 0x18000)}, [][]byte{barFrame(0, 0x10001, 0xffff)}},
		{"eth/bar where bar.entries[0].x[0:9] == 0x1ab",
			[][]byte{barFrame(0, 0x1abcd)}, [][]byte{barFrame(0, 0x0bcd)}},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			r := NewWithVocab(t, tc.expr, specs)
			for i, p := range tc.match {
				r.MustMatch(t, p, fmt.Sprintf("match #%d", i))
			}
			for i, p := range tc.reject {
				r.MustReject(t, p, fmt.Sprintf("reject #%d", i))
			}
		})
	}
	for _, expr := range []string{
		"eth/bar where bar.entries[0].y == 1",
		"eth/bar where bar.entries[bar.idx].y == 1",
		"eth/bar[entries[0].y == 1]",
	} {
		_, err := kunai.CompileWithVocab(expr, specs, codegen.Capabilities{})
		if !errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "past its 8-byte entry") {
			t.Errorf("%s: err %v, want ErrNotImplemented past the entry", expr, err)
		}
	}
}

// bazEntry packs one 16-byte entry: r(1) w(64) pad(7) a(32) pad2(24),
// with r and the padding set so a missing mask shows.
func bazEntry(w uint64, a uint32) []byte {
	b := make([]byte, 16)
	// Bits 0..72: r, w, pad as one 72-bit big-endian run.
	b[0] = 0x80 | byte(w>>57)
	for i := 1; i <= 7; i++ {
		b[i] = byte(w >> (57 - 8*i))
	}
	b[8] = byte(w<<7) | 0x7f
	b[9], b[10], b[11], b[12] = byte(a>>24), byte(a>>16), byte(a>>8), byte(a)
	b[13], b[14], b[15] = 0xff, 0xff, 0xff
	return b
}

func bazFrame(idx byte, entries ...[]byte) []byte {
	pkt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb7, byte(len(entries)), idx, 0, 0}
	for _, e := range entries {
		pkt = append(pkt, e...)
	}
	return pkt
}

// TestAuxStackUnalignedSplitSlice reads a 64-bit field at bit 1 of a
// 16-byte entry, whose [0:64] slice straddles 9 bytes (split load), by a
// static and a runtime index; the ninth byte holds w's last bit. The
// window is bytes 0..9 of the entry (auxFieldWindow's unit rows pin one
// that ends the entry). The bare field is refused, as for a primary
// field.
func TestAuxStackUnalignedSplitSlice(t *testing.T) {
	specs, err := loadUnalignedStackVocab()
	if err != nil {
		t.Fatalf("vocab: %v", err)
	}
	const w = 0x8123456789abcdef
	for _, expr := range []string{
		"eth/baz where baz.entries[1].w[0:64] == 0x8123456789abcdef",
		"eth/baz where baz.entries[baz.idx].w[0:64] == 0x8123456789abcdef",
	} {
		t.Run(expr, func(t *testing.T) {
			r := NewWithVocab(t, expr, specs)
			r.MustMatch(t, bazFrame(1, bazEntry(0, 0), bazEntry(w, 0)), "entry 1, ends the frame")
			r.MustReject(t, bazFrame(1, bazEntry(0, 0), bazEntry(w^1, 0)), "last bit (ninth byte) differs")
			r.MustReject(t, bazFrame(1, bazEntry(0, 0), bazEntry(w^(1<<63), 0)), "first bit differs")
			r.MustReject(t, bazFrame(1, bazEntry(w, 0), bazEntry(0, 0)), "entry 0 holds it")
			r.MustReject(t, bazFrame(1, bazEntry(w, 0)), "no entry 1")
		})
	}
	r := NewWithVocab(t, "eth/baz where baz.entries[baz.idx].w[0:64] == 0x8123456789abcdef", specs)
	r.MustMatch(t, bazFrame(2, bazEntry(0, 0), bazEntry(0, 0), bazEntry(w, 0)), "runtime index 2")
	r.MustReject(t, bazFrame(2, bazEntry(0, 0), bazEntry(w, 0), bazEntry(0, 0)), "runtime index 2, entry 1 holds it")
	// Unsliced, the field takes a single load, which cannot cover 9 bytes
	// (as for a primary field).
	expr := "eth/baz where baz.entries[1].w == 1"
	if _, err := kunai.CompileWithVocab(expr, specs, codegen.Capabilities{}); !errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), "needs a window over 8 bytes") {
		t.Errorf("%s: err %v, want ErrNotImplemented for a 9-byte window", expr, err)
	}
}

// TestAuxWalkCallbackNeedsByteAlignedField: an any() network-literal
// compare over a stack of more than staticAuxCap entries runs in a
// bpf_loop callback only when the field (or slice) starts and ends on
// bytes of the entry; the callback compares whole bytes. w[0:32] is
// bits 1..33 of the entry and unrolls, read as a number.
func TestAuxWalkCallbackNeedsByteAlignedField(t *testing.T) {
	specs, err := loadUnalignedStackVocab()
	if err != nil {
		t.Fatalf("vocab: %v", err)
	}
	usesCallback := func(t *testing.T, expr string) bool {
		t.Helper()
		out, err := kunai.CompileWithVocab(expr, specs, codegen.Capabilities{})
		if err != nil {
			t.Fatalf("Compile(%q): %v", expr, err)
		}
		for _, ins := range out.Callbacks {
			if strings.Contains(ins.Symbol(), "auxwalk_cb") {
				return true
			}
		}
		return false
	}
	aligned := "eth/baz where any(baz.entries.a == 10.0.0.1)"
	unaligned := "eth/baz where any(baz.entries.w[0:32] == 10.0.0.1)"
	if !usesCallback(t, aligned) {
		t.Errorf("%s: want the bpf_loop callback", aligned)
	}
	if usesCallback(t, unaligned) {
		t.Errorf("%s: want the unrolled walk", unaligned)
	}
	ip := uint64(0x0a000001)
	r := NewWithVocab(t, unaligned, specs)
	r.MustMatch(t, bazFrame(0, bazEntry(0, 0), bazEntry(ip<<32|0xffffffff, 0)), "entry 1 holds 10.0.0.1")
	r.MustReject(t, bazFrame(0, bazEntry(0, 0x0a000001), bazEntry((ip+1)<<32, 0)), "no entry holds it")
	r = NewWithVocab(t, aligned, specs)
	r.MustMatch(t, bazFrame(0, bazEntry(^uint64(0), 0), bazEntry(0, 0x0a000001)), "entry 1 holds 10.0.0.1")
	r.MustReject(t, bazFrame(0, bazEntry(0x0a000001<<32, 0)), "only w holds it")
}
