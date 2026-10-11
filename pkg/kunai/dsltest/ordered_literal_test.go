package dsltest

import (
	"net"
	"testing"
)

// TestBracketIPv4Ordered: an IPv4 literal orders as the unsigned number
// of its four bytes, so 10.0.0.2 > 10.0.0.1 and 200.1.1.1 >= 128.0.0.0.
func TestBracketIPv4Ordered(t *testing.T) {
	src := func(ip string) []byte {
		o := Defaults()
		o.SrcIP = net.ParseIP(ip)
		return Build(t, o)
	}
	gt := New(t, "eth/ipv4[src > 10.0.0.1]/tcp")
	gt.MustReject(t, src("10.0.0.1"), "equal is not greater")
	gt.MustMatch(t, src("10.0.0.2"), "one above")
	gt.MustMatch(t, src("10.0.1.0"), "a higher octet")
	gt.MustReject(t, src("9.255.255.255"), "below in the first octet")

	le := New(t, "eth/ipv4[src <= 10.0.0.1]/tcp")
	le.MustMatch(t, src("10.0.0.1"), "equal")
	le.MustMatch(t, src("9.255.255.255"), "below")
	le.MustReject(t, src("10.0.0.2"), "above")

	// Unsigned order: an address with its top bit set is large. (A Word
	// load zero-extends, so this cannot tell a signed jump from an
	// unsigned one; TestBracketIPv6Ordered does, with bit 63 of a half.)
	ge := New(t, "eth/ipv4[src >= 128.0.0.0]/tcp")
	ge.MustMatch(t, src("200.1.1.1"), "the high bit set is a large unsigned number")
	ge.MustReject(t, src("127.255.255.255"), "just below the high bit")

	lt := New(t, "eth/ipv6[dst[96:128] < 10.0.0.1]/tcp")
	lt.MustMatch(t, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::900:1"), 1234, 80), "the sliced word 9.0.0.1 is below")
	lt.MustReject(t, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::a00:1"), 1234, 80), "the sliced word is equal")
}

// TestBracketIPv6Ordered: two DWord halves compared as unsigned numbers;
// the high half decides when it differs, the low half otherwise. Bit 63
// of a half crossing between the field and the literal tells an
// unsigned jump from a signed one.
func TestBracketIPv6Ordered(t *testing.T) {
	src := func(ip string) []byte {
		return BuildEthIPv6TCP(t, net.ParseIP(ip), net.ParseIP("fc00::a00:1"), 1234, 80)
	}
	dst := func(ip string) []byte {
		return BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP(ip), 1234, 80)
	}
	lt := New(t, "eth/ipv6[src < fc00::1]/tcp")
	lt.MustMatch(t, src("fc00::"), "one below")
	lt.MustReject(t, src("fc00::1"), "equal")
	lt.MustMatch(t, src("2001:db8::1"), "the high half decides: 0x2001… is below 0xfc00… unsigned although only the literal's top bit is set")
	lt.MustReject(t, src("fc00:1::"), "the high half decides against: fc00:1:: is above fc00::1")

	le := New(t, "eth/ipv6[src <= fc00::1]/tcp")
	le.MustMatch(t, src("fc00::1"), "equal")
	le.MustReject(t, src("fc00::2"), "one above in the low half")

	gt := New(t, "eth/ipv6[dst > fc00::1]/tcp")
	gt.MustMatch(t, dst("fc00:0:0:0:8000::"), "the low half's top bit set is a large unsigned number")
	gt.MustMatch(t, dst("fc00:1::"), "the high half decides")
	gt.MustReject(t, dst("fc00::1"), "equal")
	gt.MustReject(t, dst("fc00::"), "one below")

	ge := New(t, "eth/ipv6[dst >= fc00::a00:1]/tcp")
	ge.MustMatch(t, dst("fc00::a00:1"), "equal")
	ge.MustReject(t, dst("fc00::a00:0"), "one below in the low half")
}

// TestBracketMACOrdered: the first four octets decide a strict
// inequality; when they are equal the last two octets do.
func TestBracketMACOrdered(t *testing.T) {
	srcMAC := func(mac string) []byte {
		o := Defaults()
		o.SrcMAC = mustMAC(mac)
		return Build(t, o)
	}
	lt := New(t, "eth[src < aa:bb:cc:dd:ee:02]/ipv4/tcp")
	lt.MustMatch(t, srcMAC("aa:bb:cc:dd:ee:01"), "below in the last octet")
	lt.MustReject(t, srcMAC("aa:bb:cc:dd:ee:02"), "equal")
	lt.MustReject(t, srcMAC("aa:bb:cc:dd:ee:03"), "above in the last octet")
	lt.MustMatch(t, srcMAC("aa:bb:cc:dc:ff:ff"), "decided by the first four octets, below")
	lt.MustReject(t, srcMAC("aa:bb:cc:de:00:00"), "decided by the first four octets, above")

	ge := New(t, "eth[dst >= aa:bb:cc:dd:ee:02]/ipv4/tcp")
	ge.MustMatch(t, Build(t, Defaults()), "the default destination is equal")
	ge.MustMatch(t, func() []byte { o := Defaults(); o.DstMAC = mustMAC("ff:ff:ff:ff:ff:ff"); return Build(t, o) }(), "broadcast is the largest")
	ge.MustReject(t, func() []byte { o := Defaults(); o.DstMAC = mustMAC("00:00:00:00:00:01"); return Build(t, o) }(), "a small address")
}

// TestBracketSrv6SegmentOrdered: an ordered IPv6 compare on a static
// segment index reads the entry after the count guard, so an absent
// entry is false.
func TestBracketSrv6SegmentOrdered(t *testing.T) {
	segs := func(ips ...string) []byte {
		var s []net.IP
		for _, ip := range ips {
			s = append(s, net.ParseIP(ip))
		}
		return BuildSRv6(t, SRv6Opts{Segments: s, InnerNextHeader: 6})
	}
	lt := New(t, "eth/ipv6/srv6[segments[1].addr < fc00::3]/tcp")
	lt.MustMatch(t, segs("fc00::1", "fc00::2"), "segments[1] below")
	lt.MustReject(t, segs("fc00::1", "fc00::3"), "segments[1] equal")
	lt.MustReject(t, segs("fc00::1", "fc00:1::"), "segments[1] above in the high half")
	lt.MustReject(t, segs("fc00::1"), "segments[1] absent (D-031)")

	ge := New(t, "eth/ipv6/srv6[segments[0].addr >= fc00::1]/tcp")
	ge.MustMatch(t, segs("fc00::1", "fc00::2"), "segments[0] equal")
	ge.MustReject(t, segs("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fc00::2"), "segments[0] just below in the high half")

	// Sliced windows of a segment order as their own width.
	word := New(t, "eth/ipv6/srv6[segments[1].addr[96:128] > 0.0.0.1]/tcp")
	word.MustMatch(t, segs("fc00::1", "fc00::2"), "the low word 0.0.0.2 is above")
	word.MustReject(t, segs("fc00::1", "fc00::1"), "the low word 0.0.0.1 is equal")
	mac := New(t, "eth/ipv6/srv6[segments[1].addr[80:128] < 00:00:00:00:00:03]/tcp")
	mac.MustMatch(t, segs("fc00::1", "fc00::2"), "the low 48 bits are below")
	mac.MustReject(t, segs("fc00::1", "fc00::3"), "equal")
}
