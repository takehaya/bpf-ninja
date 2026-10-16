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
// and any()/all() readers.
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
	return vocab.Load(fstest.MapFS{
		"vocab/eth.p4": &fstest.MapFile{Data: []byte(ethSrc)},
		"vocab/bar.p4": &fstest.MapFile{Data: []byte(barSrc)},
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
