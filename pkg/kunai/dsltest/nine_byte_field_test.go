package dsltest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// loadNineByteVocab is eth plus a protocol `qux` whose 18-byte header
// holds two fields that start off a byte boundary and straddle 9 bytes:
// w, 64 bits at bit 1, and u, 58 bits at bit 79 (bit 7 of byte 9). No
// bundled field has this shape; it is read like its [0:width] slice,
// through the split load.
var loadNineByteVocab = sync.OnceValues(func() (map[string]*vocab.ProtocolSpec, error) {
	const ethSrc = `
header eth_h { bit<48> dst; bit<48> src; bit<16> ethertype; }
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	const quxSrc = `
header qux_h { bit<1> r; bit<64> w; bit<7> pad; bit<7> z; bit<58> u; bit<7> pad2; }
const bit<16> KUNAI_QUX_ETH_ETHERTYPE = 0x88b9;
parser QuxParser(packet_in pkt, out qux_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	return vocab.Load(fstest.MapFS{
		"vocab/eth.p4": &fstest.MapFile{Data: []byte(ethSrc)},
		"vocab/qux.p4": &fstest.MapFile{Data: []byte(quxSrc)},
	}, "vocab")
})

// quxFrame packs eth + qux with w and u, every other header bit set so a
// missing mask shows. The header ends the frame.
func quxFrame(w, u uint64) []byte {
	ones := func(n uint) *big.Int { return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), n), big.NewInt(1)) }
	v := new(big.Int)
	put := func(x *big.Int, width uint) { v.Lsh(v, width).Or(v, x) }
	put(big.NewInt(1), 1)
	put(new(big.Int).SetUint64(w), 64)
	put(ones(7), 7)
	put(ones(7), 7)
	put(new(big.Int).SetUint64(u&(1<<58-1)), 58)
	put(ones(7), 7)
	hdr := v.FillBytes(make([]byte, 18))
	return append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb9}, hdr...)
}

// TestNineBytePrimaryField reads unsliced primary fields whose bits
// straddle 9 bytes, through where, brackets, ordering, in-lists,
// arithmetic and a set key, and checks they compile to the same code as
// their [0:width] slices.
func TestNineBytePrimaryField(t *testing.T) {
	specs, err := loadNineByteVocab()
	if err != nil {
		t.Fatalf("vocab: %v", err)
	}
	const w, u = 0x8123456789abcdef, 0x2abcdef01234567
	for _, tc := range []struct {
		expr          string
		match, reject [][]byte
	}{
		{"eth/qux where qux.w == 0x8123456789abcdef",
			[][]byte{quxFrame(w, 0)}, [][]byte{quxFrame(w^1, 0), quxFrame(w^(1<<63), 0)}},
		{"eth/qux[w == 0x8123456789abcdef]",
			[][]byte{quxFrame(w, u)}, [][]byte{quxFrame(w^1, u)}},
		{"eth/qux[w in [1, 0x8123456789abcdef]]",
			[][]byte{quxFrame(1, 0), quxFrame(w, 0)}, [][]byte{quxFrame(2, 0)}},
		{"eth/qux where qux.w > 0x8000000000000000",
			[][]byte{quxFrame(w, 0)}, [][]byte{quxFrame(0x8000000000000000, 0), quxFrame(1, 0)}},
		{"eth/qux where qux.u == 0x2abcdef01234567",
			[][]byte{quxFrame(0, u)}, [][]byte{quxFrame(0, u^1), quxFrame(0, u^(1<<57))}},
		{"eth/qux where qux.u + 1 == 0x2abcdef01234568",
			[][]byte{quxFrame(0, u)}, [][]byte{quxFrame(0, u+1)}},
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
	for _, pair := range [][2]string{
		{"eth/qux where qux.w == 5", "eth/qux where qux.w[0:64] == 5"},
		{"eth/qux where qux.u > 5", "eth/qux where qux.u[0:58] > 5"},
		{"eth/qux[w in [1, 2]]", "eth/qux[w[0:64] in [1, 2]]"},
		{"eth/qux where qux.u == 1 capture headers", "eth/qux where qux.u[0:58] == 1 capture headers"},
	} {
		assertSameCode(t, specs, pair[0], pair[1])
	}
	// A set key of such a field is its 64-bit value (spec keyBytes: 8).
	for _, tc := range []struct {
		expr string
		want uint64
	}{
		{"eth/qux[w in @k]", w},
		{"eth/qux[u in @k]", u},
	} {
		caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: newSpecSetSlots([]specSet{{Name: "k", Width: 64}})}}
		out, err := kunai.CompileWithVocab(tc.expr, specs, caps)
		if err != nil {
			t.Fatalf("Compile(%q): %v", tc.expr, err)
		}
		r := NewFromOutput(t, tc.expr, out, 0)
		matched, region := r.MatchKey(t, quxFrame(w, u))
		if !matched {
			t.Fatalf("%s: the filter rejected the packet", tc.expr)
		}
		if got := r.SetKey(t, region, "k"); !bytes.Equal(got, binary.NativeEndian.AppendUint64(nil, tc.want)) {
			t.Errorf("%s: key %x, want %#x", tc.expr, got, tc.want)
		}
	}
}
