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
}
