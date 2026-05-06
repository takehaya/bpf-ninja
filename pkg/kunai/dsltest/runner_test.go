package dsltest

import (
	"encoding/binary"
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

// TestAuxPredicateGtpOptNextExt exercises the single-aux predicate
// codegen: gating reads (gtp[0] & 0x07) and rejects when zero (= opt
// not present), then reads byte 11 (= gtp+8+3 = opt.next_ext) and
// compares with the literal. A frame with E/S/PN clear should be
// rejected because the gate fails (no opt extracted) — even though
// numerically that same byte happens to be zero in the wire.
func TestAuxPredicateGtpOptNextExt(t *testing.T) {
	r := New(t, "eth/ipv4/udp/gtp[opt.next_ext==0]/ipv4/tcp")
	matchPkt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x32, // version=1, pt=1, s=1 → opt extracted
		MsgType: 0xff,
		Opt:     &GTPOpt{Seq: 0x1234, NextExt: 0},
	})
	r.MustMatch(t, matchPkt, "gtp.opt.next_ext == 0 with opt present")

	mismatchExt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x34, // E=1 → opt with non-zero next_ext (chain follows)
		MsgType: 0xff,
		Opt:     &GTPOpt{NextExt: 0xc0},
		Exts: []GTPExt{
			{ExtLength: 1, ExtType: 0x0001, NextExt: 0},
		},
	})
	r.MustReject(t, mismatchExt, "gtp.opt.next_ext != 0 (= 0xc0)")

	noOpt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x30, // E=S=PN=0 → opt absent, gate fails
		MsgType: 0xff,
	})
	r.MustReject(t, noOpt, "opt absent (E|S|PN clear) — gate fails, predicate fails")
}

// TestAuxPredicateGtpOptInWhere covers the same predicate written in
// the where clause form: `where gtp.opt.next_ext == 0`. Same gating
// + read shape, just exercised through the where path instead of
// the bracket path.
func TestAuxPredicateGtpOptInWhere(t *testing.T) {
	r := New(t, "eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0")
	matchPkt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x32,
		MsgType: 0xff,
		Opt:     &GTPOpt{Seq: 0x1234, NextExt: 0},
	})
	r.MustMatch(t, matchPkt, "where gtp.opt.next_ext == 0 with opt present")

	noOpt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x30,
		MsgType: 0xff,
	})
	r.MustReject(t, noOpt, "where gtp.opt.next_ext == 0 with opt absent — gate fails")
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

// TestAuxStackGtpExtsIndex0 reads the first GTP extension's
// ext_type via static aux header stack index `gtp.exts[0]`. The
// ext stack starts at offset 12 (gtp_h 8 + gtp_opt_h 4); ext_type
// is at +1 (after the 1-byte ext_length), so the read lands at
// scratch byte gtp_layer_offset + 13.
func TestAuxStackGtpExtsIndex0(t *testing.T) {
	r := New(t, "eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[0].ext_type == 1")
	matchPkt := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x34, // E=1 → opt + ext
		MsgType: 0xff,
		Opt:     &GTPOpt{NextExt: 0xc0},
		Exts: []GTPExt{
			{ExtLength: 1, ExtType: 1, NextExt: 0},
		},
	})
	r.MustMatch(t, matchPkt, "gtp.exts[0].ext_type == 1")

	mismatch := BuildGTPU(t, GTPUOpts{
		TEID:    0xdeadbeef,
		Flags:   0x34,
		MsgType: 0xff,
		Opt:     &GTPOpt{NextExt: 0xc0},
		Exts: []GTPExt{
			{ExtLength: 1, ExtType: 0x0099, NextExt: 0},
		},
	})
	r.MustReject(t, mismatch, "gtp.exts[0].ext_type != 1 (= 0x99)")
}

// TestAuxStackSrv6SegmentsStaticIndex reads the first SRv6 segment
// (= final destination, segment[0] in wire order) via static index
// access. SRH segments live in the variable trail of srv6_h: the
// resolver places the stack base at offset 8 (= sizeof(srv6_h)) and
// segment[0] starts there.
func TestAuxStackSrv6SegmentsStaticIndex(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::1")
	matchPkt := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fc00::1")},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, matchPkt, "first segment == fc00::1")

	mismatch := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fc00::beef")},
		InnerNextHeader: 6,
	})
	r.MustReject(t, mismatch, "first segment != fc00::1 (= fc00::beef)")
}

// TestAuxStackSrv6SegmentsStaticCIDRMatch pins the static-stack +
// IPv6 CIDR aux combination — `srv6.segments[0].addr == fc00::/16`
// emits the same R5 = layer_anchor + OffsetInLayer + Static*ElemSize
// shape as the host case, then AND-masks the half words before the
// per-half compare. Mirrors TestAuxStackSrv6SegmentsStaticIndex with
// a prefix match.
func TestAuxStackSrv6SegmentsStaticCIDRMatch(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::/16")
	matchPkt := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fc00:abcd::1")},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, matchPkt, "first segment in fc00::/16")

	mismatch := BuildSRv6(t, SRv6Opts{
		Segments:        []net.IP{net.ParseIP("fd00::1")},
		InnerNextHeader: 6,
	})
	r.MustReject(t, mismatch, "first segment in fd00::/16, not fc00::/16")
}

// TestAuxStackSrv6SegmentsAnyCIDRMatch combines the `any(...)`
// quantifier with an IPv6 CIDR literal — the rebind path turns the
// iterator into a static index per iter, and the per-iter body
// emits the same masked half compare shape as the static-index case.
func TestAuxStackSrv6SegmentsAnyCIDRMatch(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp where any(srv6.segments.addr == 2001:db8::/32)")
	matchPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("2001:db8:abcd::42"),
			net.ParseIP("fc00::3"),
		},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, matchPkt, "any(segments.addr in 2001:db8::/32) — middle segment matches")

	missPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fd00::1"),
		},
		InnerNextHeader: 6,
	})
	r.MustReject(t, missPkt, "any(segments.addr in 2001:db8::/32) — no segment matches")
}

// TestAuxStackSrv6SegmentsAnyMatch covers the `any(...)` quantifier:
// the iter target is srv6.segments and the predicate fires when at
// least one segment equals the literal. Static unrolls 8 iterations
// (= stack capacity), each guarded by `iter < srv6.last_entry+1` so
// out-of-range reads can't accidentally match in the bytes past the
// real segment list.
func TestAuxStackSrv6SegmentsAnyMatch(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::2)")
	matchPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::2"),
			net.ParseIP("fc00::3"),
		},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, matchPkt, "any(segments.addr == fc00::2) — middle segment matches")

	missPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::3"),
		},
		InnerNextHeader: 6,
	})
	r.MustReject(t, missPkt, "any(segments.addr == fc00::2) — no segment matches")
}

// TestAuxStackSrv6SegmentsAllMatch covers `all(...)`: every segment
// must satisfy the predicate. With the count guard, iterations
// beyond the actual segment count are skipped from the all() vote.
func TestAuxStackSrv6SegmentsAllMatch(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp where all(srv6.segments.addr == fc00::1)")
	matchPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::1"),
		},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, matchPkt, "all(segments.addr == fc00::1) — all three match")

	mixedPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::2"),
			net.ParseIP("fc00::1"),
		},
		InnerNextHeader: 6,
	})
	r.MustReject(t, mixedPkt, "all(segments.addr == fc00::1) — middle segment differs")
}

// TestAuxStackSrv6SegmentsDynamicIndex reads the segment at the
// runtime index `srv6.last_entry`. With 3 segments wire-order
// [fc00::1, fc00::2, fc00::3], last_entry == 2 so the read picks
// fc00::3 (= the next hop). The codegen path: load byte at
// srv6_h[4], JGE-bound-check vs capacity 8, multiply by 16, add to
// stack base, LDX two 8-byte halves.
func TestAuxStackSrv6SegmentsDynamicIndex(t *testing.T) {
	r := New(t, "eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr == fc00::3")
	matchPkt := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::2"),
			net.ParseIP("fc00::3"),
		},
		InnerNextHeader: 6,
	})
	r.MustMatch(t, matchPkt, "segments[last_entry] == fc00::3")

	mismatch := BuildSRv6(t, SRv6Opts{
		Segments: []net.IP{
			net.ParseIP("fc00::1"),
			net.ParseIP("fc00::2"),
			net.ParseIP("fc00::99"),
		},
		InnerNextHeader: 6,
	})
	r.MustReject(t, mismatch, "segments[last_entry] != fc00::3 (= fc00::99)")
}

// TestAuxStackIpv6ExtsIndex0 reads the first IPv6 extension's
// next_header via `ipv6.exts[0].next_header`. The ext stack starts
// at offset 40 (ipv6_h size); next_header is byte 0 of an ext.
func TestAuxStackIpv6ExtsIndex0(t *testing.T) {
	r := New(t, "eth/ipv6/tcp where ipv6.exts[0].next_header == 6")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0,  // HBH
		Exts:            []IPv6Ext{{NextHeader: 6, HdrExtLen: 0, Options: bytes16("hbh-payload")}},
		FinalNextHeader: 6, // TCP
	})
	r.MustMatch(t, pkt, "first ipv6 ext.next_header == 6 (= TCP)")
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
// must accept frames with or without a VLAN tag, and reject frames
// whose ethertype is neither IPv4 nor 0x8100 (= no VLAN, no plain
// IPv4 either — must not silently skip past the optional tag and
// "succeed" on garbage).
func TestVlanQuestionMarkOptional(t *testing.T) {
	r := New(t, "eth/vlan?/ipv4/tcp")
	r.MustMatch(t, BuildEthIPv4TCP(t, 1, 80), "no VLAN tag")
	o := Defaults()
	o.VLAN = []uint16{100}
	r.MustMatch(t, Build(t, o), "one VLAN tag")
	// Reject: IPv6 ethertype (0x86DD) — neither plain IPv4 nor VLAN.
	o6 := Defaults()
	o6.SrcIP = net.ParseIP("fe80::1")
	o6.DstIP = net.ParseIP("fe80::2")
	r.MustReject(t, Build(t, o6), "ipv6 ethertype must reject vlan? filter")
}

// TestMplsPlusChain covers the `+` (1+) MPLS chain via bpf_loop.
// Reject case pins that a non-MPLS ethertype frame fails the chain
// dispatch rather than spinning the bpf_loop on garbage.
func TestMplsPlusChain(t *testing.T) {
	r := New(t, "eth/mpls+/ipv4/tcp")
	o := Defaults()
	o.MPLS = []uint32{16, 17}
	r.MustMatch(t, Build(t, o), "eth+2xMPLS+ipv4+tcp")
	// Reject: plain IPv4 frame — no MPLS labels, dispatch must fail.
	r.MustReject(t, BuildEthIPv4TCP(t, 1, 80), "no-MPLS frame must reject mpls+ filter")
}

// TestIPIPLayered exercises the layered ipv4-in-ipv4 chain
// `eth/ipv4/ipv4/tcp`. Backed by IPV4_IPV4_PROTOCOL = 4 in ipv4.p4,
// each ipv4 layer runs its own parser machine — so the inner ipv4
// can carry options (IHL>5) and the IHL-driven trailer skip still
// advances R4 to the right TCP byte. The IHL>5 case is the use case
// the chain quantifier `ipv4+` cannot handle (chain emit advances by
// fixed hs).
func TestIPIPLayered(t *testing.T) {
	r := New(t, "eth/ipv4/ipv4/tcp")

	// Inner IHL=5 (no options): fixed 20-byte inner.
	r.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{}), "outer+inner(IHL=5)+tcp")

	// Inner IHL=6 (Router Alert option, 4 bytes): inner header is 24
	// bytes. Layered chain handles this because the inner parser
	// machine reads IHL and advances accordingly.
	withOpts := BuildEthIPIPTCP(t, IPIPOpts{
		InnerOptions: []layers.IPv4Option{
			{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}},
		},
	})
	r.MustMatch(t, withOpts, "outer+inner(IHL=6, Router Alert)+tcp")

	// Negative: plain UDP frame must reject.
	r.MustReject(t, BuildEthIPv4UDP(t, 53, 53, []byte("dns")), "single-ipv4 UDP vs ipv4/ipv4/tcp filter")
}

// TestIPv6inIPv6Layered mirrors TestIPIPLayered for the v6-in-v6
// layered chain. Backed by IPV6_IPV6_NEXT_HEADER = 41.
func TestIPv6inIPv6Layered(t *testing.T) {
	r := New(t, "eth/ipv6/ipv6/tcp")
	r.MustMatch(t, BuildEthIPv6inIPv6TCP(t), "eth+ipv6(outer)+ipv6(inner)+tcp")
}

// TestIPv4OptionsWalkBoundary exercises the parser-counter-driven
// IPv4 options walk at IHL boundaries: IHL=5 (no options, fast path
// via demand-driven bulk-advance) and IHL=6/7 (Router Alert option,
// single/double walk iter). The `where ipv4.options.RR.kind` predicate
// is used to force the demand walker into emitting the actual walk
// (not the bulk-advance short-circuit) so the per-iter offset accounting
// is exercised — IHL=5 must land at TCP after a 0-byte advance,
// IHL=6 after consuming the 4-byte Router Alert.
func TestIPv4OptionsWalkBoundary(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")

	// IHL=5: no options.
	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "IHL=5 (no options)")

	// IHL=6: 4 bytes of Router Alert (kind=148, length=4).
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{
		{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}},
	}
	r.MustMatch(t, Build(t, o), "IHL=6 with Router Alert")

	// IHL=7: 2 Router Alert options (8 bytes total).
	o2 := Defaults()
	o2.IPv4Options = []layers.IPv4Option{
		{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}},
		{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 1}},
	}
	r.MustMatch(t, Build(t, o2), "IHL=7 with 2 Router Alerts")
}

// TestIPv6ExtMidChain pins the IPv6 ext-header walk's accounting
// when Fragment (fixed 8-byte) is sandwiched between variable-trail
// neighbours. This shape has different bpf_loop offset accounting
// than the trailing-Fragment case covered by TestIPv6FragmentExt.
func TestIPv6ExtMidChain(t *testing.T) {
	r := New(t, "eth/ipv6/tcp")
	pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0, // HBH
		Exts: []IPv6Ext{
			{HdrExtLen: 1, NextHeader: 44, Options: bytes16("HBH option pad")},
			{HdrExtLen: 0, NextHeader: 60}, // Fragment in the middle
			{HdrExtLen: 1, NextHeader: 6, Options: bytes16("DestOpt pad")},
		},
		FinalNextHeader: 6,
	})
	r.MustMatch(t, pkt, "eth/ipv6/HBH/Fragment/DestOpt/tcp (mid-chain Fragment)")
}

// TestQinQLeaf exercises QinQ as the leaf-most before IPv4 (= no
// inner VLAN), i.e. ethernet → QinQ tag → IPv4 (vs the more common
// QinQ + inner VLAN form).
func TestQinQLeaf(t *testing.T) {
	r := New(t, "eth/qinq/ipv4/tcp")
	o := Defaults()
	o.QinQ = true
	o.VLAN = []uint16{200}
	r.MustMatch(t, Build(t, o), "eth+QinQ+ipv4+tcp")
}

// TestVXLANDispatch exercises the vxlan vocab: UDP dport 4789
// dispatch + 8-byte VXLAN extract. Reject case pins that mismatched
// UDP dport (e.g. dport=53 for DNS) refuses to dispatch into vxlan.
// (24-bit VNI predicate is not yet supported by codegen — field size
// 3 bytes is staged.)
func TestVXLANDispatch(t *testing.T) {
	r := New(t, "eth/ipv4/udp/vxlan")
	r.MustMatch(t, BuildEthIPv4UDPVXLAN(t, 0x010203), "vxlan dispatch + extract")
	r.MustReject(t, BuildEthIPv4UDP(t, 12345, 53, []byte("dns")), "non-vxlan UDP (dport=53) must reject vxlan filter")
}

// TestGeneveDispatch exercises the geneve vocab: UDP dport 6081 +
// 8-byte fixed Geneve extract. Same shape as VXLAN with a richer
// vocab (version, opt_len, flags, protocol_type, vni, reserved).
func TestGeneveDispatch(t *testing.T) {
	r := New(t, "eth/ipv4/udp/geneve")
	r.MustMatch(t, BuildEthIPv4UDPGeneve(t, 0x040506), "geneve dispatch + extract")
	r.MustReject(t, BuildEthIPv4UDP(t, 12345, 53, []byte("dns")), "non-geneve UDP (dport=53) must reject geneve filter")
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

// TestIPv4OptionsAdvance exercises IPv4 HDRLEN: an IPv4 frame
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

// TestIPv4OptionsRRKind pins the dispatched-but-extracted aux path
// for the RR option (kind=7). The slot prelude records R3-at-entry
// as the rr base before parse_record_route fires, so DSL queries
// reach kind / length / pointer at slot+0/+1/+2.
func TestIPv4OptionsRRKind(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.options.RR.kind == 7")
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{{
		OptionType:   7,
		OptionLength: 11,
		OptionData:   make([]byte, 9), // 1 IPv4 addr + pointer + 4 unused
	}}
	r.MustMatch(t, Build(t, o), "RR option present, kind byte at slot reads 7")

	noRR := Defaults()
	noRR.IPv4Options = []layers.IPv4Option{{
		OptionType:   148, // Router Alert
		OptionLength: 4,
		OptionData:   []byte{0x00, 0x00},
	}}
	r.MustReject(t, Build(t, noRR), "no RR option — slot stays at sentinel")
}

// TestIPv4OptionsRRAddrStaticIndex exercises owner-bound stack +
// IPv4 literal compare on `ipv4.options.RR.addrs[0].addr ==
// 10.0.0.1`. Address compute is slot[rr] + OffsetAfterOwner +
// 0*ElemSize + FieldByteOff = slot+3+0+0 = slot+3.
func TestIPv4OptionsRRAddrStaticIndex(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.options.RR.addrs[0].addr == 10.0.0.1")
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{{
		OptionType:   7,
		OptionLength: 11,
		// pointer (1 byte) + addrs[0] (4 bytes) + addrs[1] (4 bytes; unused).
		OptionData: append([]byte{4}, append([]byte{10, 0, 0, 1}, 0, 0, 0, 0)...),
	}}
	r.MustMatch(t, Build(t, o), "addrs[0].addr == 10.0.0.1 matches")

	mismatch := Defaults()
	mismatch.IPv4Options = []layers.IPv4Option{{
		OptionType:   7,
		OptionLength: 11,
		OptionData:   append([]byte{4}, append([]byte{10, 0, 0, 2}, 0, 0, 0, 0)...),
	}}
	r.MustReject(t, Build(t, mismatch), "addrs[0].addr != 10.0.0.1")
}

// TestIPv4OptionsRRAddrAnyQuantifier exercises any() over the RR
// addrs stack. Capacity is 9 (max addresses in a 39-byte option);
// runtime count comes from (rr.length - 3) / 4.
func TestIPv4OptionsRRAddrAnyQuantifier(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where any(ipv4.options.RR.addrs.addr == 192.168.1.1)")
	// Two-address RR: pointer + addr0 + addr1, length = 3 + 8 = 11.
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{{
		OptionType:   7,
		OptionLength: 11,
		OptionData:   append([]byte{4}, append([]byte{10, 0, 0, 1}, 192, 168, 1, 1)...),
	}}
	r.MustMatch(t, Build(t, o), "any: addrs[1] = 192.168.1.1 matches")

	noMatch := Defaults()
	noMatch.IPv4Options = []layers.IPv4Option{{
		OptionType:   7,
		OptionLength: 11,
		OptionData:   append([]byte{4}, append([]byte{10, 0, 0, 1}, 10, 0, 0, 2)...),
	}}
	r.MustReject(t, Build(t, noMatch), "no addr matches 192.168.1.1")
}

// TestTCPMalformedUnknownOptShortLength pins the MAX_DEPTH-bounded
// behaviour for malformed TCP options whose length byte is 0 or 1.
// parse_unknown_opt reads the length via lookahead and advances R3
// by `length` bytes; for length<2 R3 fails to clear the kind+length
// pair and the dispatch re-enters at the same (or near-same)
// position. Without a guard this would spin forever; instead the
// bpf_loop callback's MAX_DEPTH=32 cap fires and the program
// returns. The verdict isn't pinned (the chain may match or reject
// depending on where R3 lands relative to scratchEnd), but the
// program MUST complete without timing out or panicking — Match()
// returning at all is the implicit assertion.
//
// This locks in B-2a's "soft" behaviour: a length<2 guard inside
// the bpf_loop body inflates verifier scalar IDs past the 1M insn
// limit on kernels 6.1/6.6/6.12/6.18, so kunai relies on MAX_DEPTH
// for termination. The runner is shared across the two cases so we
// pay for one DSL compile + verifier load instead of two.
func TestTCPMalformedUnknownOptShortLength(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	for _, tc := range []struct {
		name       string
		lengthByte byte
	}{
		{"LengthZero", 0},
		{"LengthOne", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.Match(t, buildMalformedUnknownOpt(t, tc.lengthByte))
		})
	}
}

// buildMalformedUnknownOpt crafts an Ethernet/IPv4/TCP frame with a
// hand-rolled TCP option region: kind=99 (unknown), length=lengthByte,
// followed by a 2-byte filler so the TCP header lands on a 4-byte
// boundary. data_offset is set to 6 (24-byte header).
func buildMalformedUnknownOpt(t *testing.T, lengthByte byte) []byte {
	t.Helper()
	pkt := BuildEthIPv4TCP(t, 12345, 80)
	// pkt structure: eth (14) + ipv4 (20) + tcp (20). Append 4 bytes
	// of options to reach a 24-byte TCP header.
	const tcpStart = 14 + 20
	const dataOffByte = tcpStart + 12 // tcp byte 12 holds (doff << 4) | reserved
	// Bump data_offset from 5 to 6: upper nibble at byte 12.
	pkt[dataOffByte] = (6 << 4) | (pkt[dataOffByte] & 0x0F)
	// Append 4-byte option region: kind=99, length=N, 2 bytes pad.
	opt := []byte{99, lengthByte, 0, 0}
	pkt = append(pkt, opt...)
	// Patch IPv4 total_length (offset eth+2..eth+4) to include the
	// extra 4 bytes. Original total = ipv4 header (20) + tcp header
	// (20) = 40. New total = 40 + 4 = 44.
	const ipv4TotalLenOff = 14 + 2
	binary.BigEndian.PutUint16(pkt[ipv4TotalLenOff:ipv4TotalLenOff+2], 44)
	// IPv4 header checksum needs recompute, but the BPF parser doesn't
	// validate the checksum — leaving it stale is harmless for this
	// test.
	return pkt
}

// TestIPv4OptionsRejectsTooShort confirms the IHL underflow guard:
// a hand-crafted frame with IHL=4 (< 5) must be rejected by the
// HDRLEN MinimumTotal check.
func TestIPv4OptionsRejectsTooShort(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	pkt := BuildEthIPv4TCP(t, 12345, 80)
	// Patch the version+IHL byte at offset 14 (eth header is 14B).
	// Original is 0x45 (v=4, ihl=5); set to 0x44 (ihl=4 — invalid).
	pkt[ethHeaderSize] = 0x44
	r.MustReject(t, pkt, "ipv4 with IHL=4 should be rejected")
}

// TestTCPOptionsAdvance exercises TCP HDRLEN. A TCP frame with
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
// the HDRLEN advance ((IHL & 0x0F) * 4 - 20 = 40) to confirm
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

// TestTCPOptionLookupMSSValue exercises the option-walk codegen:
// `tcp.options.MSS.value == 1460` scans the TCP options area until
// it finds kind=2 (MSS) and reads its 16-bit value field.
func TestTCPOptionLookupMSSValue(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460")
	matchOpts := Defaults()
	matchOpts.TCPOptions = []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4}, // 1460
	}}
	r.MustMatch(t, Build(t, matchOpts), "MSS.value == 1460")

	mismatchOpts := Defaults()
	mismatchOpts.TCPOptions = []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xa0}, // 1440
	}}
	r.MustReject(t, Build(t, mismatchOpts), "MSS.value == 1440 vs filter 1460")

	// MSS absent → walk reaches end-of-options without match → reject.
	noMSSOpts := Defaults()
	noMSSOpts.TCPOptions = []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{7},
	}}
	r.MustReject(t, Build(t, noMSSOpts), "MSS option absent — walk fails to find")
}

// TestTCPOptionLookupSkipUnknown exercises the unknown-kind branch:
// MSS lives behind a Window Scale option, so the walk must read WS's
// length byte and advance correctly to find MSS at the next position.
func TestTCPOptionLookupSkipUnknown(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
	}
	r.MustMatch(t, Build(t, o), "WS first, MSS second — walk skips unknown")
}

// TestTCPOptionLookupNopPadding exercises the padding (NOP) branch:
// NOP options advance R3 by 1 byte without a length field. MSS lives
// after several NOPs so the walk must advance past them correctly.
func TestTCPOptionLookupNopPadding(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
	}
	r.MustMatch(t, Build(t, o), "MSS after 2 NOPs — walk advances past padding")
}

// TestTCPOptionLookupSACKKind pins the dispatched-but-not-extracted
// aux path: tcp_opt_sack_h is declared as an `out` param but never
// extracted; the slot prelude records SACK's per-packet base when
// the dispatch case kind=5 fires, and predicate codegen reads the
// kind / length bytes from slot+0 / slot+1. A packet with a SACK
// option (1 block = 10 bytes) following NOP padding must route
// through parse_sack's lookahead-driven advance to land on the next
// option's kind without state explosion in the bpf_loop callback.
func TestTCPOptionLookupSACKKind(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.SACK.kind == 5")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		sackOption([2]uint32{1, 5}),
	}
	r.MustMatch(t, Build(t, o), "SACK option present — kind byte at slot reads 5")

	// Same chain but no SACK option → the dispatch never targets
	// parse_sack so the slot prelude leaves the SACK slot at its
	// sentinel; predicate access must reject.
	noSack := Defaults()
	noSack.TCPOptions = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
	}
	r.MustReject(t, Build(t, noSack), "SACK absent — slot stays at sentinel, predicate rejects")
}

// sackOption packs N {left, right} edge pairs into a TCPOption with
// kind=5 and the matching `2 + 8*N` length byte. Each pair is written
// big-endian (network order) so the byte literal in tests reads as
// the field value the DSL predicate compares against.
func sackOption(blocks ...[2]uint32) layers.TCPOption {
	data := make([]byte, 8*len(blocks))
	for i, b := range blocks {
		binary.BigEndian.PutUint32(data[i*8:], b[0])
		binary.BigEndian.PutUint32(data[i*8+4:], b[1])
	}
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACK,
		OptionLength: uint8(2 + 8*len(blocks)),
		OptionData:   data,
	}
}

// TestTCPOptionLookupSACKBlockStaticIndex pins the static index path
// for option-internal arrays — `tcp.options.SACK.blocks[0].left ==
// 0x12345678` reads the first 4-byte block edge at slot+2+0*8 = +2
// (the kind+length pair sits at slot+0..1, blocks start at +2).
func TestTCPOptionLookupSACKBlockStaticIndex(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.SACK.blocks[0].left == 0x12345678")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{sackOption([2]uint32{0x12345678, 0x99})}
	r.MustMatch(t, Build(t, o), "SACK blocks[0].left = 0x12345678 matches predicate")

	mismatch := Defaults()
	mismatch.TCPOptions = []layers.TCPOption{sackOption([2]uint32{0xabcdef01, 0x99})}
	r.MustReject(t, Build(t, mismatch), "different left edge — predicate rejects")
}

// TestTCPOptionLookupSACKBlockSecondIndex exercises blocks[1] — same
// shape but offset += 8 in the address compute. Two-block SACK
// option.
func TestTCPOptionLookupSACKBlockSecondIndex(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.SACK.blocks[1].right == 0x42")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{
		sackOption([2]uint32{1, 5}, [2]uint32{0x10, 0x42}),
	}
	r.MustMatch(t, Build(t, o), "SACK blocks[1].right = 0x42 matches at slot+2+8+4")
}

// TestTCPOptionLookupSACKBlockAnyQuantifier exercises the any() form
// over an option-internal array. The runtime count guard reads the
// SACK option's length byte, subtracts 2 for the kind+length pair,
// and right-shifts by 3 to get the live block count; iters past
// that count fall through to the per-iter skip without bound errors.
func TestTCPOptionLookupSACKBlockAnyQuantifier(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where any(tcp.options.SACK.blocks.left == 0x100)")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{
		sackOption([2]uint32{1, 5}, [2]uint32{0x100, 0x200}),
	}
	r.MustMatch(t, Build(t, o), "any(blocks.left == 0x100): block 1 matches")

	noMatch := Defaults()
	noMatch.TCPOptions = []layers.TCPOption{sackOption([2]uint32{0x200, 0x300})}
	r.MustReject(t, Build(t, noMatch), "single block, neither edge matches")
}

// TestTCPOptionLookupSACKBlockAllQuantifier exercises the all() form
// — every live block must satisfy the inner predicate. Vacuous truth
// when no SACK option is present (count guard rejects all iters).
func TestTCPOptionLookupSACKBlockAllQuantifier(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where all(tcp.options.SACK.blocks.right > 0)")
	o := Defaults()
	o.TCPOptions = []layers.TCPOption{
		sackOption([2]uint32{1, 5}, [2]uint32{0x10, 0x20}),
	}
	r.MustMatch(t, Build(t, o), "all blocks have right > 0")

	zero := Defaults()
	zero.TCPOptions = []layers.TCPOption{sackOption([2]uint32{1, 0})}
	r.MustReject(t, Build(t, zero), "block 0.right = 0 fails the all() predicate")
}

// TestTCPOptionsMaxDataOffset drives data_offset=15 (maximum),
// lifting the TCP header to 60 B = 40 B of options. Mirror of the
// IPv4 max-IHL stress test for the TCP HDRLEN path.
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

// TestIPv4AndTCPOptionsAdvance verifies both HDRLEN advances stack
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
