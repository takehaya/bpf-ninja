package dsltest

import "testing"

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
