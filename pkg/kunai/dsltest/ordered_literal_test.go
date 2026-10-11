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

	ge := New(t, "eth/ipv4[src >= 128.0.0.0]/tcp")
	ge.MustMatch(t, src("200.1.1.1"), "the high bit set is a large unsigned number")
	ge.MustReject(t, src("127.255.255.255"), "just below the high bit")

	lt := New(t, "eth/ipv6[dst[96:128] < 10.0.0.1]/tcp")
	lt.MustMatch(t, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::900:1"), 1234, 80), "the sliced word 9.0.0.1 is below")
	lt.MustReject(t, BuildEthIPv6TCP(t, net.ParseIP("fc00::1"), net.ParseIP("fc00::a00:1"), 1234, 80), "the sliced word is equal")
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
}
