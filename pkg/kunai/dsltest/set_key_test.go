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
// gtp exts), an IPv6 segment, a full-width slice, and 3- and 6-byte
// fields read through their 4- and 8-byte windows (a VNI, a MAC), and
// option fields off a byte boundary (OVN ingress_port, rsv).
func TestSetKeyBytes(t *testing.T) {
	native16 := func(v uint16) []byte { return binary.NativeEndian.AppendUint16(nil, v) }
	native32 := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
	native64 := func(v uint64) []byte { return binary.NativeEndian.AppendUint64(nil, v) }
	exts := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0,
		Exts:            []IPv6Ext{{NextHeader: 60, HdrExtLen: 1}, {NextHeader: 6}},
		FinalNextHeader: 6,
	})
	gtp := BuildGTPU(t, GTPUOpts{Flags: 0x34, TEID: 1, Opt: &GTPOpt{NextExt: 0x85},
		Exts: []GTPExt{{ExtLength: 2, ExtType: 0x1234, NextExt: 0x85}, {ExtLength: 1, ExtType: 0xbeef, NextExt: 0}}})
	sid := net.ParseIP("fc00::2")
	srv6 := BuildSRv6(t, SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::1"), sid}, InnerNextHeader: 6})
	ovn := BuildEthIPv4UDPGeneveOpts(t, 0x123456, GeneveOptionTLV(t, 0x0102, 0x80, ovnValue(true, 0x1234, 0xffff)))
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
		{"64-bit slice", "eth/ipv6[dst[64:128] in @k]/tcp", 64, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::102"), 1, 2), native64(0x102)},
		{"full-width slice", "eth/ipv6[dst[0:128] in @k]/tcp", 128, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), sid, 1, 2), sid.To16()},
		{"vxlan vni", "eth/ipv4/udp/vxlan[vni in @k]", 32, BuildEthIPv4UDPVXLAN(t, 0x123456), native32(0x123456)},
		{"mac src", "eth[src in @k]/ipv4/tcp", 64, BuildEthIPv4TCP(t, 1, 2), native64(0xaabbccddee01)},
		{"mac dst", "eth[dst in @k]/ipv4/tcp", 64, BuildEthIPv4TCP(t, 1, 2), native64(0xaabbccddee02)},
		{"ovn ingress port", "eth/ipv4/udp/geneve[ovn.ingress_port in @k]", 16, ovn, native16(0x1234)},
		{"ovn rsv", "eth/ipv4/udp/geneve[ovn.rsv in @k]", 8, ovn, []byte{1}},
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
			if got := r.SetKey(t, region, "k"); !bytes.Equal(got, tc.want) {
				t.Errorf("key %x, want %x (region %x)", got, tc.want, region)
			}
		})
	}
}

// TestSetKeyTwoSets: two sets take their own slots (the second below the
// first) and SetKey cuts each out; a set the filter does not extract a
// key for has none.
func TestSetKeyTwoSets(t *testing.T) {
	expr := "eth/ipv4[src in @hosts]/tcp[dport in @ports]"
	caps := codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: newSpecSetSlots([]specSet{{Name: "hosts", Width: 32}, {Name: "ports", Width: 16}, {Name: "spare", Width: 8}})}}
	out, err := kunai.Compile(expr, caps)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := NewFromOutput(t, expr, out, 0)
	matched, region := r.MatchKey(t, BuildEthIPv4TCP(t, 1, 443))
	if !matched {
		t.Fatal("the filter rejected the packet")
	}
	if got, want := r.SetKey(t, region, "hosts"), binary.NativeEndian.AppendUint32(nil, 0x0a000001); !bytes.Equal(got, want) {
		t.Errorf("hosts key %x, want %x", got, want)
	}
	if got, want := r.SetKey(t, region, "ports"), binary.NativeEndian.AppendUint16(nil, 443); !bytes.Equal(got, want) {
		t.Errorf("ports key %x, want %x", got, want)
	}
	if got := r.SetKey(t, region, "spare"); got != nil {
		t.Errorf("spare key %x, want none", got)
	}
}

// TestSetKeyRegionZeroed: the key region reads zero for a filter with no
// set, under a kunai stack filled with ones (the fill stops at
// KunaiStackTop, below the region, which the wrapper zeroes as the hosts
// do).
func TestSetKeyRegionZeroed(t *testing.T) {
	out, err := kunai.Compile("eth/ipv4/tcp", codegen.Capabilities{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := NewFromOutputStackFilled(t, "eth/ipv4/tcp", out, 0, -1)
	if _, region := r.MatchKey(t, BuildEthIPv4TCP(t, 1, 2)); region != [keyRegionSize]byte{} {
		t.Errorf("key region %x, want zero", region)
	}
}
