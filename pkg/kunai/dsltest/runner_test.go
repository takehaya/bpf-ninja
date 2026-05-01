package dsltest

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

const gtpChain = "eth/ipv4/udp/gtp/ipv4/tcp"

// TestEthIPv4TCPMatch is the canonical "filter compiles, runs, and
// classifies traffic correctly" smoke test. It compiles the
// `eth/ipv4/tcp` chain and feeds in two frames: a plain IPv4/TCP
// frame (must match) and an IPv4/UDP frame (must not match). When
// this passes we know the per-CPU scratch + bpf_xdp_load_bytes
// wrapper, the kunai filter, and the BPF_PROG_TEST_RUN plumbing
// all line up — every later case in this file builds on this
// foundation.
func TestEthIPv4TCPMatch(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "eth/ipv4/tcp frame")
	r.MustReject(t, BuildEthIPv4UDP(t, 12345, 53, []byte("query")), "UDP against eth/ipv4/tcp filter")
}

// TestEthIPv4TCPDportPredicate exercises a primary-header predicate
// (`tcp[dport==443]`). Confirms the predicate path runs in the
// scratch-buffer wrapper and that byte-swap-at-codegen handles the
// 16-bit dport correctly.
func TestEthIPv4TCPDportPredicate(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[dport==443]")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 443), "tcp dport=443")
	r.MustReject(t, BuildEthIPv4TCP(t, 12345, 80), "tcp dport=80 vs filter dport=443")
}

// TestEthIPv6TCPMatch verifies the v6 path: IPv6 next_header dispatch
// + bit<128> field handling for the source/destination addresses.
func TestEthIPv6TCPMatch(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	src := net.ParseIP("fe80::1")
	dst := net.ParseIP("fe80::2")
	r.MustMatch(t, BuildEthIPv6TCP(t, src, dst, 1234, 80), "eth/ipv6/tcp frame")
}

// TestEthIPv4SrcCIDR exercises the IPv4 CIDR predicate codegen.
func TestEthIPv4SrcCIDR(t *testing.T) {
	r := New(t, "eth/ipv4[src==10.0.0.0/8]/tcp")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "10.0.0.1 in 10.0.0.0/8")
	o := Defaults()
	o.SrcIP = net.ParseIP("172.16.0.1")
	r.MustReject(t, Build(t, o), "172.16.0.1 not in 10.0.0.0/8")
}

// TestParserMachineGTPNoFlags is the simplest GTP shape: version 1,
// pt=1, no E/S/PN — the start state's transition select takes the
// (0,0,0) -> accept branch and offsetBase advances by 8 only. The
// inner IPv4 must satisfy the NIBBLE sanity check.
func TestParserMachineGTPNoFlags(t *testing.T) {
	r := New(t, gtpChain)
	pkt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x30, // version=1, pt=1, all of e/s/pn=0
		MsgType: 0xff,
	})
	r.MustMatch(t, pkt, "plain GTP-U (no opt, no ext)")
}

// TestParserMachineGTPOpt covers the parse_opt state: any of E/S/PN
// set forces the optional 4-byte block. The opt's next_ext == 0
// terminates parsing without entering the ext chain.
func TestParserMachineGTPOpt(t *testing.T) {
	r := New(t, gtpChain)
	pkt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x32, // version=1, pt=1, s=1
		MsgType: 0xff,
		Opt:     &GTPOpt{Seq: 0x1234},
	})
	r.MustMatch(t, pkt, "GTP-U with opt block (next_ext=0)")
}

// TestParserMachineGTPExt exercises the parse_ext self-loop: opt's
// next_ext is non-zero, then exts run until next_ext == 0. Two ext
// headers here so the bpf_loop callback runs at least once.
func TestParserMachineGTPExt(t *testing.T) {
	r := New(t, gtpChain)
	pkt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x34, // version=1, pt=1, e=1
		MsgType: 0xff,
		Opt:     &GTPOpt{NextExt: 0xc0},
		Exts: []GTPExt{
			{ExtLength: 1, ExtType: 0x0001, NextExt: 0xc1},
			{ExtLength: 1, ExtType: 0x0002, NextExt: 0},
		},
	})
	r.MustMatch(t, pkt, "GTP-U with 2 ext headers")
}

// TestParserMachineGTPRejectsNonGTPDport confirms the parent-layer
// dispatch (UDP dport == 2152) still gates the GTP machine: a UDP
// frame to a different port must not enter the GTP parser at all.
func TestParserMachineGTPRejectsNonGTPDport(t *testing.T) {
	r := New(t, gtpChain)
	r.MustReject(t, BuildEthIPv4UDP(t, 12345, 53, []byte("not-gtp")), "UDP dport=53 vs GTP chain")
}

// TestParserMachineGTPRejectsTruncated covers the bounds check
// inside the GTP machine: a frame whose UDP payload is too short to
// hold gtp_h must drop, not match, and definitely must not panic
// the verifier.
func TestParserMachineGTPRejectsTruncated(t *testing.T) {
	r := New(t, gtpChain)
	// UDP dport=2152 but only 3 payload bytes — gtp_h needs 8.
	r.MustReject(t, BuildEthIPv4UDP(t, 12345, 2152, []byte{0x30, 0xff, 0x00}), "truncated GTP frame")
}

// TestVlanChainOneTag covers the fixed-count VLAN chain.
func TestVlanChainOneTag(t *testing.T) {
	r := New(t, "eth/vlan{1,1}/ipv4/tcp")
	o := Defaults()
	o.VLAN = []uint16{100}
	r.MustMatch(t, Build(t, o), "eth+1xVLAN+ipv4+tcp")
}

// TestVlanChainTwoTags covers the two-tag double-VLAN shape (both
// outer and inner have ethertype 0x8100 — the self-stack pattern
// VLAN_VLAN_ETHERTYPE encodes; QinQ uses 0x88a8 and is a separate
// protocol).
func TestVlanChainTwoTags(t *testing.T) {
	r := New(t, "eth/vlan{2,2}/ipv4/tcp")
	o := Defaults()
	o.VLAN = []uint16{100, 200}
	r.MustMatch(t, Build(t, o), "eth+2xVLAN+ipv4+tcp")
}

// TestVlanQuestionMarkOptional covers the `?` quantifier: filter
// must accept frames with or without a VLAN tag.
func TestVlanQuestionMarkOptional(t *testing.T) {
	r := New(t, "eth/vlan?/ipv4/tcp")
	r.MustMatch(t, BuildEthIPv4TCP(t, 1, 80), "no VLAN tag")
	o := Defaults()
	o.VLAN = []uint16{100}
	r.MustMatch(t, Build(t, o), "one VLAN tag")
}

// TestMplsPlusChain covers the `+` (1+) MPLS chain via bpf_loop.
func TestMplsPlusChain(t *testing.T) {
	r := New(t, "eth/mpls+/ipv4/tcp")
	o := Defaults()
	o.MPLS = []uint32{16, 17}
	r.MustMatch(t, Build(t, o), "eth+2xMPLS+ipv4+tcp")
}

// TestEthIPv4UDPDirect ensures the simple UDP path still works
// alongside the GTP-over-UDP path. Important regression check
// because both filters share the udp.p4 vocab.
func TestEthIPv4UDPDirect(t *testing.T) {
	r := New(t, "eth/ipv4/udp")
	r.MustMatch(t, BuildEthIPv4UDP(t, 53, 53, []byte("dns")), "eth/ipv4/udp DNS frame")
	r.MustReject(t, BuildEthIPv4TCP(t, 12345, 80), "TCP frame vs eth/ipv4/udp filter")
}

// TestIPv6FragmentExt covers the fixed-size case of the ipv6 ext
// chain: Fragment (44) is always 8 bytes (HdrExtLen=0) so the
// variable trailing skip resolves to zero extra bytes. Filter
// `eth/ipv6/tcp` still matches because the parser machine walks
// past the Fragment header before the inner TCP dispatch.
func TestIPv6FragmentExt(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 44, // Fragment
		Exts:            []IPv6Ext{{HdrExtLen: 0}},
		FinalNextHeader: 6, // TCP
	})
	r.MustMatch(t, pkt, "eth/ipv6/Fragment/tcp")
}

// TestIPv6HopByHopExt exercises the variable trailing skip: HBH
// with HdrExtLen=1 means a 16-byte HBH ext header. The codegen
// must read hdr_ext_len, shift left 3, and advance by that many
// extra bytes after the fixed 8-byte prefix.
func TestIPv6HopByHopExt(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0, // HBH
		Exts:            []IPv6Ext{{HdrExtLen: 1, Options: bytes16("HBH option pad")}},
		FinalNextHeader: 6,
	})
	r.MustMatch(t, pkt, "eth/ipv6/HBH(16B)/tcp")
}

// TestIPv6MultipleExts walks two ext headers (HBH then DestOpt) so
// the parse_ext self-loop runs at least one bpf_loop iteration
// past the initial inline pass.
func TestIPv6MultipleExts(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0, // HBH
		Exts: []IPv6Ext{
			{HdrExtLen: 0}, // HBH 8B
			{HdrExtLen: 0}, // DestOpt 8B
		},
		FinalNextHeader: 6,
	})
	r.MustMatch(t, pkt, "eth/ipv6/HBH/DestOpt/tcp")
}

// TestIPv6NoExts is the negative-control case: a frame with no ext
// headers must still match `eth/ipv6/tcp`. Confirms the start
// state's `default: accept` branch is reached without entering the
// ext chain at all.
func TestIPv6NoExts(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 6, // TCP — no ext headers
		FinalNextHeader: 6,
	})
	r.MustMatch(t, pkt, "eth/ipv6/tcp (no ext headers)")
}

// TestSRv6OneSegment exercises the SRv6 chain with a single segment
// (= SRH total size 24 bytes: 8 fixed + 16 segment). Confirms the
// variable trail shifts R4 past the segment list and the inner TCP
// dispatch reads SRH.next_header.
func TestSRv6OneSegment(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp")
	pkt := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fe80::dead")},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, pkt, "eth/ipv6/srv6 (1 segment)/tcp")
}

// TestSRv6ThreeSegments stresses the variable advance: 3 segments =
// 48 bytes after the SRH fixed prefix (= hdr_ext_len 6, near the
// LenMask=0x07 ceiling). Confirms the codegen propagates the
// segments_left/last_entry triple correctly even at chain depth.
func TestSRv6ThreeSegments(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp")
	pkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fe80::1111"),
			net.ParseIP("fe80::2222"),
			net.ParseIP("fe80::3333"),
		},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, pkt, "eth/ipv6/srv6 (3 segments)/tcp")
}

// TestIPv4OptionsAdvance exercises IPv4 VAREXT_LEN: an IPv4 frame
// with one Record-Route option (option type 7, length 11) lifts IHL
// to 8 (32-byte header). Codegen must read IHL, multiply by 4,
// subtract 20, and advance R4 by 12 so the TCP layer's dispatch
// sees the right bytes.
func TestIPv4OptionsAdvance(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{{
		OptionType:   7, // Record Route
		OptionLength: 11,
		OptionData:   make([]byte, 9), // 11-byte option = type+len+9 data
	}}
	r.MustMatch(t, Build(t, o), "ipv4 with options + tcp")
}

// TestIPv4OptionsRejectsTooShort confirms the IHL underflow guard:
// a hand-crafted frame with IHL=4 (< 5) must be rejected by the
// VAREXT MinimumTotal check.
func TestIPv4OptionsRejectsTooShort(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	pkt := BuildEthIPv4TCP(t, 12345, 80)
	// Patch the version+IHL byte at offset 14 (eth header is 14B).
	// Original is 0x45 (v=4, ihl=5); set to 0x44 (ihl=4 — invalid).
	pkt[ethHeaderSize] = 0x44
	r.MustReject(t, pkt, "ipv4 with IHL=4 should be rejected")
}

// TestTCPOptionsAdvance exercises TCP VAREXT_LEN. A TCP frame with
// one MSS option (kind 2, length 4) plus EOL padding lifts
// data_offset to 6 (24-byte header). Codegen reads byte 12, masks
// upper nibble, shifts right 4, multiplies by 4, subtracts 20.
func TestTCPOptionsAdvance(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4}, // MSS = 1460
	}}
	r.MustMatch(t, Build(t, o), "ipv4 + tcp with MSS option")
}

// TestIPv4OptionsMaxIHL drives IHL=15 (the maximum legal value),
// which lifts the IPv4 header to 60 B = 40 B of options. Stresses
// the VAREXT advance ((IHL & 0x0F) * 4 - 20 = 40) to confirm
// codegen narrows the advance correctly under the 512 B scratch.
func TestIPv4OptionsMaxIHL(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	o := Defaults()
	// Two Record-Route options of 19 B each + 2 NOPs = 40 B options.
	// Sum must be a multiple of 4; FixLengths in gopacket adjusts IHL.
	o.IPv4Options = []layers.IPv4Option{
		{OptionType: 7, OptionLength: 19, OptionData: make([]byte, 17)},
		{OptionType: 7, OptionLength: 19, OptionData: make([]byte, 17)},
		{OptionType: 1}, // NOP (no length, no data)
		{OptionType: 1}, // NOP
	}
	r.MustMatch(t, Build(t, o), "ipv4 IHL=15 (40B options) + tcp")
}

// TestTCPOptionsMaxDataOffset drives data_offset=15 (maximum),
// lifting the TCP header to 60 B = 40 B of options. Mirror of the
// IPv4 max-IHL stress test for the TCP VAREXT path.
func TestTCPOptionsMaxDataOffset(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	o := Defaults()
	// 40 B of TCP options: a Timestamp (10 B) + MSS (4 B) + Window
	// Scale (3 B) + several NOPs to reach 40 — gopacket recomputes
	// data_offset to fit. We pad to 40 explicitly with NOPs.
	o.TCPOptions = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
	}
	for range 23 {
		o.TCPOptions = append(o.TCPOptions, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
	}
	r.MustMatch(t, Build(t, o), "tcp data_offset=15 (40B options)")
}

// TestParserMachineGTPOptNoExt exercises an edge case in the GTP
// parser machine: E flag set so the optional 4 B block is present,
// but opt.next_ext = 0 so the ext loop terminates without iterating.
// Verifies the state-machine transition select takes (1,0,0)→opt
// then opt.next_ext==0→done without calling bpf_loop.
func TestParserMachineGTPOptNoExt(t *testing.T) {
	r := New(t, gtpChain)
	pkt := BuildGTPU(t, GTPUOpts{
		TEID:  0xdeadbeef,
		Flags: 0x34, // version=1, pt=1, e=1
		Opt:   &GTPOpt{Seq: 0x1234, NPDU: 0, NextExt: 0},
	})
	r.MustMatch(t, pkt, "gtp E=1 opt.next_ext=0 (chain immediate term)")
}

// TestIPv6ExtTruncatedHdrExtLen patches an IPv6 HBH ext header to
// claim hdr_ext_len that would advance past the packet end. The
// per-iteration bounds JGT must reject the frame before the read.
func TestIPv6ExtTruncatedHdrExtLen(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0, // HBH
		FinalNextHeader: 6, // TCP
		Exts:            []IPv6Ext{{NextHeader: 6, HdrExtLen: 1, Options: bytes16("hbh1")}},
	})
	// First ext sits at eth(14)+ipv6(40)=54. Byte 1 is hdr_ext_len.
	// Crank it to 0xFF so the per-iter advance ((0xFF<<3)+8 capped by
	// LenMask=0x03 = 32 B) still pushes past packet end across iters.
	// Even with the cap, 4 iterations × 32 = 128 B exceeds the 1-ext
	// frame's payload, so bounds JGT must fire on iter 1.
	pkt[ethIPv6PrefixSize+1] = 0xFF
	r.MustReject(t, pkt, "ipv6 ext with oversized hdr_ext_len")
}

// TestSRv6MalformedSegmentsMismatch inverts the routing-type guard
// case: routing_type=4 stays valid, but the SRH advertises
// last_entry / segments_left that disagree with the byte-actual
// segment list. Codegen reads only last_entry so the malformed
// segments_left shouldn't prevent a match — pin the current
// behaviour so future SRH-aware predicates know what they are
// observing.
func TestSRv6MalformedSegmentsMismatch(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp")
	pkt := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fe80::dead")},
		InnerNextHeader: 6,
	})
	// SRH starts at eth+ipv6 = 54. Bytes 3 (segments_left) and 4
	// (last_entry) — set both to 7 even though only one segment is
	// actually present. The variable trail uses hdr_ext_len (byte 1
	// = 2 = "16-byte segment count of 1"), so we don't touch it; the
	// counters are advisory.
	pkt[ethIPv6PrefixSize+3] = 7
	pkt[ethIPv6PrefixSize+4] = 7
	r.MustMatch(t, pkt, "srv6 with mismatched segments_left/last_entry still matches")
}

// TestIPv4AndTCPOptionsAdvance verifies both VAREXT advances stack
// correctly: IPv4 options + TCP options together.
func TestIPv4AndTCPOptionsAdvance(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[dport==443]")
	o := Defaults()
	o.DstPort = 443
	o.IPv4Options = []layers.IPv4Option{{
		OptionType:   7, // Record Route
		OptionLength: 11,
		OptionData:   make([]byte, 9),
	}}
	o.TCPOptions = []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4},
	}}
	r.MustMatch(t, Build(t, o), "ipv4(opts) + tcp(opts) dport=443")
}

// TestGREFlags drives every C/K/S combination of the GRE optional
// sub-headers through one filter (= one compile + load). Each
// subtest reuses the runner so the verifier-load cost is paid once;
// per-case packet construction confirms codegen advances R4 by the
// right cumulative amount in declaration order (C → K → S).
func TestGREFlags(t *testing.T) {
	r := New(t, "eth/ipv4/gre/ipv4/tcp")
	cases := []struct {
		name string
		opts GREOpts
	}{
		{"NoOptionals", GREOpts{}},
		{"Checksum", GREOpts{HasChecksum: true}},
		{"KeyAndSequence", GREOpts{HasKey: true, HasSequence: true, Key: 0xdeadbeef, Sequence: 1}},
		{"All", GREOpts{HasChecksum: true, HasKey: true, HasSequence: true, Key: 0xcafebabe, Sequence: 42}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r.MustMatch(t, BuildGRE(t, c.opts), "gre/"+c.name)
		})
	}
}

// TestCaptureToLayerLoads compiles a chain that captures up to a
// labeled inner layer. Capture is host-side (the compiled BPF only
// emits the kunai filter; the host wrapper consumes Output.Capture
// .MaxCapLen separately), so this test focuses on the BPF program
// loading verifier-clean — packet match correctness is covered by
// the codegen unit tests.
func TestCaptureToLayerLoads(t *testing.T) {
	r := New(t, "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner+8")
	r.MustMatch(t, BuildGTPU(t, GTPUOpts{TEID: 0xdeadbeef}), "filter still matches GTP frames")
}

// TestCaptureAbsoluteLoads pins the absolute-byte-count form
// through the same load path.
func TestCaptureAbsoluteLoads(t *testing.T) {
	r := New(t, "eth/ipv4/tcp capture absolute 64")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "filter unaffected by absolute capture sizing")
}

// TestWhereIPv4Literal exercises `where field == ipv4_literal`.
// Previously this required hex (`== 0x0a000002`); the parser now
// accepts dotted-quad in value mode so the user-facing form is
// readable.
func TestWhereIPv4Literal(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.dst == 10.0.0.2")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "ipv4.dst == 10.0.0.2 should match Defaults() frame")

	o := Defaults()
	o.DstIP = net.ParseIP("10.0.0.99")
	r.MustReject(t, Build(t, o), "ipv4.dst != 10.0.0.2 should be rejected")
}

// TestWhereIPv4CIDR exercises `where field == 10.0.0.0/8` — same
// prefix-match semantic as the predicate-form `[dst == 10.0.0.0/8]`,
// expressed in a where clause so it can compose with `and`/`or`.
func TestWhereIPv4CIDR(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.dst == 10.0.0.0/8")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "10.0.0.2 in 10.0.0.0/8")

	o := Defaults()
	o.DstIP = net.ParseIP("172.16.0.1")
	r.MustReject(t, Build(t, o), "172.16.0.1 outside 10.0.0.0/8")
}

// TestWhereIPv6Literal pins where-form IPv6 host comparisons through
// the multi-word route (== / != only).
func TestWhereIPv6Literal(t *testing.T) {
	r := New(t, "eth/ipv6/tcp where ipv6.dst == fe80::2")
	src := net.ParseIP("fe80::1")
	dst := net.ParseIP("fe80::2")
	r.MustMatch(t, BuildEthIPv6TCP(t, src, dst, 1234, 80), "ipv6.dst == fe80::2")

	wrong := net.ParseIP("fe80::99")
	r.MustReject(t, BuildEthIPv6TCP(t, src, wrong, 1234, 80), "ipv6.dst != fe80::2")
}

// TestWhereMACLiteral pins where-form MAC literal compares.
func TestWhereMACLiteral(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where eth.dst == aa:bb:cc:dd:ee:02")
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "Defaults() eth.dst is aa:bb:cc:dd:ee:02")
}

// TestWhereCombinedWithIntPredicate ensures the where-side IP literal
// path coexists with integer arithmetic comparisons in the same
// clause (and/or composition).
func TestWhereCombinedWithIntPredicate(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.dst == 10.0.0.2 and tcp.dport == 443")
	o := Defaults()
	o.DstPort = 443
	r.MustMatch(t, Build(t, o), "ipv4.dst==10.0.0.2 and tcp.dport==443")
	r.MustReject(t, BuildEthIPv4TCP(t, 12345, 80), "tcp.dport=80 fails AND")
}

// TestEthIPv4ESPMatch verifies ESP terminal-layer dispatch works
// over IPv4. Inner ESP payload is "encrypted" (opaque bytes) — the
// chain match must succeed off the 8-byte SPI/seq prefix alone.
func TestEthIPv4ESPMatch(t *testing.T) {
	r := New(t, "eth/ipv4/esp")
	r.MustMatch(t, BuildEthIPv4ESP(t, 0xdeadbeef, 1), "eth/ipv4/esp frame")
	r.MustReject(t, BuildEthIPv4TCP(t, 12345, 80), "tcp must not match esp filter")
}

// TestEthIPv6ESPMatch is the IPv6 counterpart.
func TestEthIPv6ESPMatch(t *testing.T) {
	r := New(t, "eth/ipv6/esp")
	src := net.ParseIP("fe80::1")
	dst := net.ParseIP("fe80::2")
	r.MustMatch(t, BuildEthIPv6ESP(t, src, dst, 0xcafebabe, 99), "eth/ipv6/esp frame")
	r.MustReject(t, BuildEthIPv6TCP(t, src, dst, 1234, 80), "tcp must not match esp filter")
}

// TestSRv6RejectsNonSRHRouting confirms the routing_type guard:
// SRH demands routing_type==4, so a plain Routing header (type 0
// or 3) must not be classified as SRv6.
func TestSRv6RejectsNonSRHRouting(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp")
	pkt := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fe80::dead")},
		InnerNextHeader: 6,
	})
	// SRH starts right after eth+ipv6 (= ethIPv6PrefixSize). Patch
	// routing_type (byte 2 of SRH) to 0 — a deprecated source-routing
	// variant that the parser must reject.
	pkt[ethIPv6PrefixSize+2] = 0
	r.MustReject(t, pkt, "non-SRH routing_type=0 should not match")
}
