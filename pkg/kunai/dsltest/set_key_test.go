package dsltest

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// TestSetKeyBytes reads back the key an `in @set` predicate leaves in the
// host's key region and compares it with the bytes `set add` writes for
// the field's value: native-endian for a field of at most 8 bytes, network
// order for a 16-byte one. It covers a primary field, a slice, a static
// stack entry, entries found by walking variable-length ones (ipv6 exts,
// gtp exts) and an IPv6 segment.
func TestSetKeyBytes(t *testing.T) {
	native16 := func(v uint16) []byte { return binary.NativeEndian.AppendUint16(nil, v) }
	native32 := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
	exts := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0,
		Exts:            []IPv6Ext{{NextHeader: 60, HdrExtLen: 1}, {NextHeader: 6}},
		FinalNextHeader: 6,
	})
	gtp := BuildGTPU(t, GTPUOpts{Flags: 0x34, TEID: 1, Opt: &GTPOpt{NextExt: 0x85},
		Exts: []GTPExt{{ExtLength: 2, ExtType: 0x1234, NextExt: 0x85}, {ExtLength: 1, ExtType: 0xbeef, NextExt: 0}}})
	sid := net.ParseIP("fc00::2")
	srv6 := BuildSRv6(t, SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::1"), sid}, InnerNextHeader: 6})
	for _, tc := range []struct {
		name, expr string
		width      int
		pkt        []byte
		want       []byte
	}{
		{"primary", "eth/ipv4[src in @k]/tcp", 32, BuildEthIPv4TCP(t, 1, 2), native32(0x0a000001)},
		{"slice", "eth/ipv4[dst[24:32] in @k]/tcp", 8, BuildEthIPv4TCP(t, 1, 2), []byte{2}},
		{"port", "eth/ipv4/tcp[dport in @k]", 16, BuildEthIPv4TCP(t, 1, 443), native16(443)},
		{"ipv6 walked entry", "eth/ipv6[exts[1].next_header in @k]/tcp", 8, exts, []byte{6}},
		{"gtp walked entry", "eth/ipv4/udp/gtp[exts[1].ext_type in @k]/ipv4/tcp", 16, gtp, native16(0xbeef)},
		{"srv6 segment", "eth/ipv6/srv6[segments[1].addr in @k]/tcp", 128, srv6, sid.To16()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: newSpecSetSlots([]specSet{{Name: "k", Width: tc.width}})}}
			out, err := kunai.Compile(tc.expr, caps)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.expr, err)
			}
			r := NewFromOutput(t, tc.expr, out, 0)
			matched, region := r.MatchKey(t, tc.pkt)
			if !matched {
				t.Fatalf("the filter rejected the packet; region %x", region)
			}
			if got := r.SetKey(region, "k"); !bytes.Equal(got, tc.want) {
				t.Errorf("key %x, want %x (region %x)", got, tc.want, region)
			}
		})
	}
}
