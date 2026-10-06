package dsltest

import (
	"sync"
	"testing"
	"testing/fstest"

	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// failRegionVocab is eth plus a protocol `foo` whose option region is
// declared in bytes (len_words × 4) and annotated on_fault=fail: a fault
// in the region rejects the packet (spec D-029), whatever the filter
// reads. Only a NOP (kind 1) is a known option.
var loadFailRegionVocab = sync.OnceValues(func() (map[string]*vocab.ProtocolSpec, error) {
	const ethSrc = `
header eth_h { bit<48> dst; bit<48> src; bit<16> ethertype; }
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	const fooSrc = `
header foo_h { bit<8> kind; bit<8> len_words; bit<16> tag; }
const bit<16> KUNAI_FOO_ETH_ETHERTYPE = 0x88b5;
const bit<8> FOO_MAX_DEPTH = 8;
extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}
@kunai_option_region[on_fault=fail]
parser FooParser(packet_in pkt, out foo_h hdr) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.len_words - 0)) << 5);
        transition walk;
    }
    state walk {
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true, _):  accept;
            (false, 1): parse_nop;
            (false, _): reject;
        }
    }
    state parse_nop { pkt.advance(8); pc.decrement(1); transition walk; }
}
`
	return vocab.Load(fstest.MapFS{
		"vocab/eth.p4": &fstest.MapFile{Data: []byte(ethSrc)},
		"vocab/foo.p4": &fstest.MapFile{Data: []byte(fooSrc)},
	}, "vocab")
})

// TestOptionRegionFailRejectsWhateverTheFilterReads: with on_fault=fail
// the walk runs even when the filter reads nothing in the region, so a
// malformed region rejects for every filter; a well-formed one matches.
func TestOptionRegionFailRejectsWhateverTheFilterReads(t *testing.T) {
	specs, err := loadFailRegionVocab()
	if err != nil {
		t.Fatalf("vocab: %v", err)
	}
	frame := func(region ...byte) []byte {
		pkt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb5, 0, 1, 0, 7}
		return append(append(pkt, region...), 'a', 'a', 'a', 'a')
	}
	good, bad := frame(1, 1, 1, 1), frame(1, 0x09, 1, 1)
	for _, expr := range []string{"eth/foo", "eth/foo where foo.tag == 7"} {
		r := NewWithVocab(t, expr, specs)
		r.MustMatch(t, good, expr+": well-formed region")
		r.MustReject(t, bad, expr+": malformed region (on_fault=fail)")
	}
}
