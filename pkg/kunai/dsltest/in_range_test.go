package dsltest

import (
	"net"
	"testing"
)

// TestBracketInRange pins `field in [lo..hi]` and mixed lists in bracket
// predicates (D-011): the field is compared in host order, so the range
// bounds are inclusive and values and ranges may be mixed.
func TestBracketInRange(t *testing.T) {
	dport := func(p uint16) []byte {
		o := Defaults()
		o.DstPort = p
		return Build(t, o)
	}
	r := New(t, "eth/ipv4/tcp[dport in [79..81]]")
	r.MustReject(t, dport(78), "78 below the range")
	r.MustMatch(t, dport(79), "79 at the low bound")
	r.MustMatch(t, dport(80), "80 inside")
	r.MustMatch(t, dport(81), "81 at the high bound")
	r.MustReject(t, dport(82), "82 above the range")

	mixed := New(t, "eth/ipv4/tcp[dport in [80, 443, 8000..8080]]")
	mixed.MustMatch(t, dport(80), "listed value")
	mixed.MustMatch(t, dport(443), "listed value")
	mixed.MustMatch(t, dport(8040), "inside the range")
	mixed.MustReject(t, dport(8081), "just above the range")
	mixed.MustReject(t, dport(22), "unlisted")

	// A 32-bit field with alternatives above int32: the compare must stay
	// unsigned (register compare, not a sign-extended immediate).
	seq := func(s uint32) []byte {
		pkt := Build(t, Defaults())
		// eth(14) + ipv4(20) + tcp sport/dport(4) → seq
		pkt[38], pkt[39], pkt[40], pkt[41] = byte(s>>24), byte(s>>16), byte(s>>8), byte(s)
		return pkt
	}
	high := New(t, "eth/ipv4/tcp[seq in [1..2, 0x80000000]]")
	high.MustMatch(t, seq(1), "inside the low range")
	high.MustMatch(t, seq(0x80000000), "listed value above int32")
	high.MustReject(t, seq(0x7FFFFFFF), "unlisted")
	highRange := New(t, "eth/ipv4/tcp[seq in [0x80000000..0xFFFFFFFF]]")
	highRange.MustMatch(t, seq(0x80000000), "low bound above int32")
	highRange.MustMatch(t, seq(0xFFFFFFFF), "high bound")
	highRange.MustReject(t, seq(0x7FFFFFFF), "below the range")
}

// TestBracketInIPv4List: IPv4 hosts and CIDRs are alternatives of an `in`
// list, mixed with integers and ranges on the same bit<32> field.
func TestBracketInIPv4List(t *testing.T) {
	dst := func(ip string) []byte {
		o := Defaults()
		o.DstIP = net.ParseIP(ip)
		return Build(t, o)
	}
	src := func(ip string) []byte {
		o := Defaults()
		o.SrcIP = net.ParseIP(ip)
		return Build(t, o)
	}
	hosts := New(t, "eth/ipv4[dst in [10.0.0.2, 10.0.0.3]]/tcp")
	hosts.MustMatch(t, dst("10.0.0.2"), "first alternative")
	hosts.MustMatch(t, dst("10.0.0.3"), "second alternative")
	hosts.MustReject(t, dst("10.0.0.4"), "unlisted")

	cidr := New(t, "eth/ipv4[src in [10.0.0.0/8, 192.168.1.1]]/tcp")
	cidr.MustMatch(t, src("10.9.9.9"), "inside the /8")
	cidr.MustMatch(t, src("192.168.1.1"), "the host alternative")
	cidr.MustReject(t, src("11.0.0.1"), "outside both")
	cidr.MustReject(t, src("192.168.1.2"), "a neighbour of the host")

	mixed := New(t, "eth/ipv4[src in [10.0.0.9, 5, 167772160..167772163]]/tcp")
	mixed.MustMatch(t, src("10.0.0.9"), "the address")
	mixed.MustMatch(t, src("0.0.0.5"), "the integer, read as an address")
	mixed.MustMatch(t, src("10.0.0.1"), "inside the range")
	mixed.MustReject(t, src("10.0.0.4"), "just above the range")

	masked := New(t, "eth/ipv4[src in [10.0.0.0/8, 1..5]]/tcp")
	masked.MustMatch(t, src("10.200.0.1"), "CIDR next to a range (host order)")
	masked.MustMatch(t, src("0.0.0.3"), "inside the range")
	masked.MustReject(t, src("11.0.0.3"), "outside both")

	New(t, "eth/ipv4[src in [0.0.0.0/0, 10.0.0.1]]/tcp").MustMatch(t, src("203.0.113.7"), "a /0 alternative matches every address")

	// Prefix lengths at the ends, and a network above int32 next to a
	// range (the host-order path materialises it with a register compare).
	edges := New(t, "eth/ipv4[src in [10.0.0.2/31, 128.0.0.0/1, 10.0.0.9/32]]/tcp")
	edges.MustMatch(t, src("10.0.0.3"), "inside the /31")
	edges.MustReject(t, src("10.0.0.4"), "outside the /31")
	edges.MustMatch(t, src("200.1.1.1"), "inside 128.0.0.0/1")
	edges.MustReject(t, src("127.0.0.1"), "outside 128.0.0.0/1")
	edges.MustMatch(t, src("10.0.0.9"), "the /32 host")
	wide := New(t, "eth/ipv4[src in [200.0.0.0/8, 1..5]]/tcp")
	wide.MustMatch(t, src("200.9.9.9"), "inside the /8 above int32")
	wide.MustReject(t, src("201.0.0.1"), "outside the /8")
}

// TestBracketInIPv6List: IPv6 hosts and CIDRs reload the 16-byte field
// per alternative; masks may cover the high half, the low half or both.
func TestBracketInIPv6List(t *testing.T) {
	src := func(ip string) []byte {
		return BuildEthIPv6TCP(t, net.ParseIP(ip), net.ParseIP("fc00::a00:1"), 1234, 80)
	}
	list := New(t, "eth/ipv6[src in [fc00::1, fc00::/16]]/tcp")
	list.MustMatch(t, src("fc00::1"), "the host alternative")
	list.MustMatch(t, src("fc00:abcd::9"), "inside the /16")
	list.MustReject(t, src("fd00::1"), "outside both")

	halves := New(t, "eth/ipv6[src in [fc00::/64, fc00:1::/32]]/tcp")
	halves.MustMatch(t, src("fc00::ffff:1"), "high-half mask only")
	halves.MustMatch(t, src("fc00:1:2::3"), "/32 inside the high half")
	halves.MustReject(t, src("fc00:0:0:1::1"), "a bit outside the /64 and the /32")

	low := New(t, "eth/ipv6[src in [fc00::/100]]/tcp")
	low.MustMatch(t, src("fc00::1"), "both halves masked, low bits outside the prefix")
	low.MustReject(t, src("fc00::1000:0"), "a bit inside the low-half mask differs")

	New(t, "eth/ipv6[src in [::/0, fc00::1]]/tcp").MustMatch(t, src("2001:db8::1"), "a /0 alternative matches every address")

	// Prefix lengths at the half boundary and at the ends of the low half.
	edges := New(t, "eth/ipv6[src in [fc00:0:0:0:8000::/65, fc00::ff00/127, fc00::abcd/128]]/tcp")
	edges.MustMatch(t, src("fc00::8000:0:0:1"), "inside the /65: the top bit of the low half is set")
	edges.MustReject(t, src("fc00::1"), "outside the /65: the top bit of the low half is clear")
	edges.MustMatch(t, src("fc00::ff01"), "inside the /127")
	edges.MustReject(t, src("fc00::ff02"), "outside the /127")
	edges.MustMatch(t, src("fc00::abcd"), "the /128 host")
	half := New(t, "eth/ipv6[src in [8000::/1]]/tcp")
	half.MustMatch(t, src("fc00::1"), "/1: the top bit of fc00:: is set")
	half.MustReject(t, src("7fff::1"), "/1: the top bit is clear")

	// Inside a repeated layer every instance is checked (statically unrolled).
	one := BuildEthIPv6TCP(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1234, 80)
	two := BuildEthIPv6inIPv6TCP(t)
	rep := New(t, "eth/ipv6[src in [2001:db8::1, 2001:db8:f00::1]]{1,2}/tcp")
	rep.MustMatch(t, one, "one header, listed")
	rep.MustMatch(t, two, "two headers, both listed")
	New(t, "eth/ipv6[src in [2001:db8::2, 2001:db8:f00::/48]]{1,2}/tcp").MustReject(t, two, "the outer header is not listed")
}

// TestBracketInMACList: MAC alternatives compare the first four octets
// and the last two separately, so a frame must differ in neither.
func TestBracketInMACList(t *testing.T) {
	srcMAC := func(mac string) []byte {
		o := Defaults()
		o.SrcMAC = mustMAC(mac)
		return Build(t, o)
	}
	list := New(t, "eth[src in [aa:bb:cc:dd:ee:01, 11:22:33:44:55:66]]/ipv4/tcp")
	list.MustMatch(t, Build(t, Defaults()), "the default source")
	list.MustMatch(t, srcMAC("11:22:33:44:55:66"), "the second alternative")
	list.MustReject(t, srcMAC("aa:bb:cc:dd:ee:02"), "differs in the last two octets only")
	list.MustReject(t, srcMAC("aa:bb:cc:de:ee:01"), "differs in the first four octets only")
	// The single MAC literal shares macCheck with the list.
	eq := New(t, "eth[src == aa:bb:cc:dd:ee:01]/ipv4/tcp")
	eq.MustMatch(t, Build(t, Defaults()), "equal")
	eq.MustReject(t, srcMAC("aa:bb:cc:dd:ee:02"), "last octet differs")
	eq.MustReject(t, srcMAC("ab:bb:cc:dd:ee:01"), "first octet differs")
	ne := New(t, "eth[src != aa:bb:cc:dd:ee:01]/ipv4/tcp")
	ne.MustReject(t, Build(t, Defaults()), "equal")
	ne.MustMatch(t, srcMAC("aa:bb:cc:dd:ee:02"), "last octet differs")
	ne.MustMatch(t, srcMAC("ab:bb:cc:dd:ee:01"), "first octet differs")
	sliced := New(t, "eth/ipv6[dst[80:128] in [00:00:0a:00:00:01, 00:00:0a:00:00:02]]/tcp")
	sliced.MustMatch(t, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::a00:1"), 1234, 80), "the low 48 bits as a MAC alternative")
	sliced.MustReject(t, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::a00:3"), 1234, 80), "low 48 bits unlisted")
}

// TestBracketInSrv6SegmentList: a static segment index under an `in` list
// walks the count guard first, so an absent entry matches nothing.
func TestBracketInSrv6SegmentList(t *testing.T) {
	segs := func(ips ...string) []byte {
		var s []net.IP
		for _, ip := range ips {
			s = append(s, net.ParseIP(ip))
		}
		return BuildSRv6(t, SRv6Opts{Segments: s, InnerNextHeader: 6})
	}
	list := New(t, "eth/ipv6/srv6[segments[1].addr in [fc00::1, fc00::2]]/tcp")
	list.MustMatch(t, segs("fc00::1", "fc00::2"), "segments[1] is listed")
	list.MustReject(t, segs("fc00::1", "fc00::3"), "segments[1] is not listed")
	list.MustReject(t, segs("fc00::1"), "segments[1] is absent (D-031)")
	cidr := New(t, "eth/ipv6/srv6[segments[1].addr in [fc00::1, fc00::/16]]/tcp")
	cidr.MustMatch(t, segs("fc00::1", "fc00::2"), "inside the CIDR alternative")
	cidr.MustReject(t, segs("fc00::1", "fd00::2"), "outside both")
}

// TestBracketInSlicedIPv4List: the low 32 bits of an IPv6 address are a
// bit<32> window, so IPv4 alternatives compare the last four bytes.
func TestBracketInSlicedIPv4List(t *testing.T) {
	dst := func(ip string) []byte {
		return BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP(ip), 1234, 80)
	}
	list := New(t, "eth/ipv6[dst[96:128] in [10.0.0.1, 10.0.0.2]]/tcp")
	list.MustMatch(t, dst("fc00::a00:1"), "low word 10.0.0.1")
	list.MustMatch(t, dst("fc00::a00:2"), "low word 10.0.0.2")
	list.MustReject(t, dst("fc00::a00:3"), "low word 10.0.0.3")
	New(t, "eth/ipv6/srv6[segments[1].addr[96:128] in [0.0.0.1, 0.0.0.2]]/tcp").MustMatch(t,
		BuildSRv6(t, SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::1"), net.ParseIP("fc00::2")}, InnerNextHeader: 6}),
		"sliced segment word in the list")
}
